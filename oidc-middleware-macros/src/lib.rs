//! Handler-level authorization macros for `oidc-middleware`.
//!
//! These macros are intentionally narrow. Prefer Axum route layers when
//! authorization belongs to route structure, and use macros when the permission
//! is inseparable from a handler's business operation. The generated code checks
//! the `OidcPrincipal` extractor that the main crate populates after OIDC
//! authentication.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{FnArg, Ident, ItemFn, LitStr, Pat, ReturnType, parse_macro_input};

/// Adds a Quarkus-style role check to an Axum handler.
///
/// Use this when a role requirement is part of the handler contract rather than
/// a router-level concern. The annotated function must be async, return
/// `Result<_, oidc_middleware::Error>`, and take an `OidcPrincipal` argument
/// named `principal`. The special role `"**"` means any authenticated principal.
///
/// ```ignore
/// use oidc_middleware::{Error, OidcPrincipal, roles_allowed};
///
/// #[roles_allowed("admin")]
/// async fn admin(principal: OidcPrincipal) -> Result<&'static str, Error> {
///     Ok("admin")
/// }
/// ```
#[proc_macro_attribute]
pub fn roles_allowed(attr: TokenStream, item: TokenStream) -> TokenStream {
    let roles = parse_macro_input!(attr as RolesAllowedArgs);
    let mut function = parse_macro_input!(item as ItemFn);
    TokenStream::from(expand_roles_allowed("roles_allowed", roles, &mut function))
}

/// Requires an authenticated OIDC principal for an Axum handler.
///
/// Use this for handler-local authentication checks that do not distinguish
/// roles. The annotated function must be async, return
/// `Result<_, oidc_middleware::Error>`, and take an `OidcPrincipal` argument
/// named `principal`.
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
    parse_macro_input!(attr as AuthenticatedArgs);
    let mut function = parse_macro_input!(item as ItemFn);
    TokenStream::from(expand_roles_allowed(
        "authenticated",
        RolesAllowedArgs {
            roles: vec![LitStr::new("**", function.sig.ident.span())],
        },
        &mut function,
    ))
}

struct RolesAllowedArgs {
    roles: Vec<LitStr>,
}

struct AuthenticatedArgs;

impl syn::parse::Parse for AuthenticatedArgs {
    fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Self> {
        if !input.is_empty() {
            return Err(input.error("#[authenticated] does not accept arguments"));
        }

        Ok(Self)
    }
}

impl syn::parse::Parse for RolesAllowedArgs {
    fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Self> {
        let mut roles = Vec::new();

        while !input.is_empty() {
            let role: LitStr = input.parse()?;
            if role.value().trim().is_empty() {
                return Err(syn::Error::new_spanned(
                    role,
                    "role names must not be empty",
                ));
            }
            roles.push(role);

            if input.is_empty() {
                break;
            }
            input.parse::<syn::Token![,]>()?;
        }

        if roles.is_empty() {
            return Err(input.error("#[roles_allowed] requires at least one role"));
        }

        Ok(Self { roles })
    }
}

fn expand_roles_allowed(
    macro_name: &str,
    roles: RolesAllowedArgs,
    function: &mut ItemFn,
) -> TokenStream2 {
    let mut errors = Vec::new();

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

    if find_principal_argument(function).is_none() {
        errors.push(
            syn::Error::new_spanned(
                &function.sig.inputs,
                format!(
                    "{macro_name} handlers must take an OidcPrincipal argument named `principal`"
                ),
            )
            .to_compile_error(),
        );
    }

    if !errors.is_empty() {
        return quote! {
            #function
            #(#errors)*
        };
    }

    let authenticated_only = roles.roles.iter().any(|role| role.value() == "**");
    if !authenticated_only {
        let role_values = roles.roles.iter();
        let check = quote! {
            if !principal.has_any_group([#(#role_values),*]) {
                return ::std::result::Result::Err(::oidc_middleware::Error::Forbidden);
            }
        };
        function.block.stmts.insert(0, syn::parse_quote!(#check));
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

fn find_principal_argument(function: &ItemFn) -> Option<&Ident> {
    function.sig.inputs.iter().find_map(|input| {
        let FnArg::Typed(typed) = input else {
            return None;
        };
        let Pat::Ident(ident) = typed.pat.as_ref() else {
            return None;
        };
        (ident.ident == "principal").then_some(&ident.ident)
    })
}
