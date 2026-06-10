//! Handler-level authorization macros for `oidc-middleware`.
//!
//! These macros are intentionally narrow. Prefer Axum route layers when
//! authorization belongs to route structure, and use macros when the permission
//! is inseparable from a handler's business operation. The generated code checks
//! an `OidcAuthorize` value extracted by Axum after OIDC authentication.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{FnArg, Ident, ItemFn, LitStr, Pat, ReturnType, Token, parse_macro_input};

/// Adds a Quarkus-style role check to an Axum handler.
///
/// Use this when a role requirement is part of the handler contract rather than
/// a router-level concern. The annotated function must be async, return
/// `Result<_, oidc_middleware::Error>`, and take an argument named `principal`
/// that implements `OidcAuthorize`. The special role `"**"` means any
/// authenticated principal.
///
/// ```ignore
/// use oidc_middleware::{Error, OidcPrincipal, roles_allowed};
///
/// #[roles_allowed("admin")]
/// async fn admin(principal: OidcPrincipal) -> Result<&'static str, Error> {
///     Ok("admin")
/// }
/// ```
///
/// Application-specific extractors can be named explicitly:
///
/// ```ignore
/// use oidc_middleware::{Error, roles_allowed};
///
/// #[roles_allowed("admin", principal = user)]
/// async fn admin(user: User) -> Result<&'static str, Error> {
///     Ok("admin")
/// }
/// ```
#[proc_macro_attribute]
pub fn roles_allowed(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as RolesAllowedArgs);
    let mut function = parse_macro_input!(item as ItemFn);
    TokenStream::from(expand_roles_allowed("roles_allowed", args, &mut function))
}

/// Requires an authenticated OIDC principal for an Axum handler.
///
/// Use this for handler-local authentication checks that do not distinguish
/// roles. The annotated function must be async, return
/// `Result<_, oidc_middleware::Error>`, and take an argument named `principal`
/// that implements `OidcAuthorize`.
///
/// ```ignore
/// use oidc_middleware::{Error, OidcPrincipal, authenticated};
///
/// #[authenticated]
/// async fn profile(principal: OidcPrincipal) -> Result<String, Error> {
///     Ok(principal.subject().to_owned())
/// }
/// ```
#[proc_macro_attribute]
pub fn authenticated(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as AuthenticatedArgs);
    let mut function = parse_macro_input!(item as ItemFn);
    TokenStream::from(expand_roles_allowed(
        "authenticated",
        RolesAllowedArgs {
            roles: vec![LitStr::new("**", function.sig.ident.span())],
            principal: args.principal,
        },
        &mut function,
    ))
}

struct RolesAllowedArgs {
    roles: Vec<LitStr>,
    principal: Option<Ident>,
}

struct AuthenticatedArgs {
    principal: Option<Ident>,
}

impl syn::parse::Parse for AuthenticatedArgs {
    fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Self> {
        if input.is_empty() {
            return Ok(Self { principal: None });
        }

        Ok(Self {
            principal: Some(parse_principal_arg(input)?),
        })
    }
}

impl syn::parse::Parse for RolesAllowedArgs {
    fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Self> {
        let mut roles = Vec::new();
        let mut principal = None;

        while !input.is_empty() {
            if input.peek(LitStr) {
                let role: LitStr = input.parse()?;
                if role.value().trim().is_empty() {
                    return Err(syn::Error::new_spanned(
                        role,
                        "role names must not be empty",
                    ));
                }
                roles.push(role);
            } else {
                if principal.is_some() {
                    return Err(input.error("principal argument must be specified only once"));
                }
                principal = Some(parse_principal_arg(input)?);
            }

            if input.is_empty() {
                break;
            }
            input.parse::<Token![,]>()?;
        }

        if roles.is_empty() {
            return Err(input.error("#[roles_allowed] requires at least one role"));
        }

        Ok(Self { roles, principal })
    }
}

fn parse_principal_arg(input: syn::parse::ParseStream<'_>) -> syn::Result<Ident> {
    if !input.peek(Ident) {
        return Err(input.error("expected `principal = <argument_name>`"));
    }
    let name: Ident = input.parse()?;
    if name != "principal" {
        return Err(syn::Error::new_spanned(
            name,
            "expected `principal = <argument_name>`",
        ));
    }
    input.parse::<Token![=]>()?;
    input.parse()
}

fn expand_roles_allowed(
    macro_name: &str,
    args: RolesAllowedArgs,
    function: &mut ItemFn,
) -> TokenStream2 {
    let mut errors = Vec::new();
    let principal_ident = args
        .principal
        .unwrap_or_else(|| Ident::new("principal", function.sig.ident.span()));

    if function.sig.asyncness.is_none() {
        errors.push(
            syn::Error::new_spanned(
                &function.sig.ident,
                format!("{macro_name} handlers must be async"),
            )
            .to_compile_error(),
        );
    }

    if !returns_result(&function.sig.output) {
        errors.push(
            syn::Error::new_spanned(
                &function.sig.output,
                format!("{macro_name} handlers must return Result<_, oidc_middleware::Error>"),
            )
            .to_compile_error(),
        );
    }

    if find_argument(function, &principal_ident).is_none() {
        let message = format!(
            "{macro_name} handlers must take an OidcAuthorize argument named `{principal_ident}`"
        );
        errors.push(syn::Error::new_spanned(&function.sig.inputs, message).to_compile_error());
    }

    if !errors.is_empty() {
        return quote! {
            #function
            #(#errors)*
        };
    }

    function.block.stmts.insert(
        0,
        syn::parse_quote! {
            let _ = ::oidc_middleware::OidcAuthorize::principal(&#principal_ident);
        },
    );

    if !args.roles.iter().any(|role| role.value() == "**") {
        let role_values = args.roles.iter();
        function.block.stmts.insert(
            1,
            syn::parse_quote! {
                if !::oidc_middleware::OidcAuthorize::has_any_group(&#principal_ident, [#(#role_values),*]) {
                    return ::std::result::Result::Err(::oidc_middleware::Error::Forbidden);
                }
            }
        );
    }

    quote! {
        #function
        #(#errors)*
    }
}

fn returns_result(output: &ReturnType) -> bool {
    let ReturnType::Type(_, ty) = output else {
        return false;
    };

    let syn::Type::Path(path) = ty.as_ref() else {
        return false;
    };

    path.path
        .segments
        .last()
        .is_some_and(|segment| segment.ident == "Result")
}

fn find_argument<'a>(function: &'a ItemFn, name: &Ident) -> Option<&'a Ident> {
    function.sig.inputs.iter().find_map(|input| {
        let FnArg::Typed(typed) = input else {
            return None;
        };
        let Pat::Ident(ident) = typed.pat.as_ref() else {
            return None;
        };
        (ident.ident == *name).then_some(&ident.ident)
    })
}
