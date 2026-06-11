//! Handler-level authorization macros for `oidc-middleware`.
//!
//! These macros are intentionally narrow. Prefer Axum route layers when
//! authorization belongs to route structure, and use macros when the permission
//! is inseparable from a handler's business operation. The generated code checks
//! an `OidcAuthorize` value extracted by Axum after OIDC authentication.

#![warn(missing_docs)]

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    Data, DeriveInput, Field, Fields, FnArg, Ident, ItemFn, LitStr, Pat, ReturnType, Token,
    parse_macro_input, parse_quote,
};

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

/// Derives `OidcAuthorize` for an application-specific type.
///
/// Mark the field containing `oidc_middleware::Principal` with
/// `#[oidc(principal)]`. A field named `principal` is also accepted.
#[proc_macro_derive(OidcAuthorize, attributes(oidc))]
pub fn derive_oidc_authorize(item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    TokenStream::from(expand_oidc_authorize(&input))
}

/// Derives conversion from `Principal` plus an Axum extractor implementation.
///
/// Supported field annotations are `#[oidc(principal)]` and `#[oidc(subject)]`.
#[proc_macro_derive(FromOidcPrincipal, attributes(oidc))]
pub fn derive_from_oidc_principal(item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    TokenStream::from(expand_from_oidc_principal(&input))
}

/// Derives conversion from `OidcSession` plus an Axum extractor implementation.
///
/// Supported field annotations are `#[oidc(principal)]`, `#[oidc(subject)]`,
/// `#[oidc(id_token)]`, and `#[oidc(id_token_claim = "...")]`.
#[proc_macro_derive(FromOidcSession, attributes(oidc))]
pub fn derive_from_oidc_session(item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    TokenStream::from(expand_from_oidc_session(&input))
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

#[derive(Clone)]
enum OidcFieldKind {
    Principal,
    Subject,
    IdToken,
    IdTokenClaim(LitStr),
}

struct OidcField<'a> {
    field: &'a Field,
    ident: &'a Ident,
    kind: OidcFieldKind,
}

fn expand_oidc_authorize(input: &DeriveInput) -> TokenStream2 {
    let fields = match oidc_fields(input) {
        Ok(fields) => fields,
        Err(error) => return error.to_compile_error(),
    };
    let Some(principal) = fields
        .iter()
        .find(|field| matches!(field.kind, OidcFieldKind::Principal))
    else {
        return syn::Error::new_spanned(
            input,
            "OidcAuthorize derive requires a field marked #[oidc(principal)] or named `principal`",
        )
        .to_compile_error();
    };
    let principal_ident = principal.ident;
    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();

    quote! {
        impl #impl_generics ::oidc_middleware::OidcAuthorize for #name #type_generics #where_clause {
            fn principal(&self) -> &::oidc_middleware::Principal {
                &self.#principal_ident
            }
        }
    }
}

fn expand_from_oidc_principal(input: &DeriveInput) -> TokenStream2 {
    let fields = match oidc_fields(input) {
        Ok(fields) => fields,
        Err(error) => return error.to_compile_error(),
    };
    let initializers = match principal_initializers(input, &fields) {
        Ok(initializers) => initializers,
        Err(error) => return error.to_compile_error(),
    };
    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();
    let mut request_generics = input.generics.clone();
    request_generics.params.push(parse_quote!(S));
    request_generics
        .make_where_clause()
        .predicates
        .push(parse_quote!(S: Send + Sync));
    let (request_impl_generics, _, request_where_clause) = request_generics.split_for_impl();

    quote! {
        impl #impl_generics ::oidc_middleware::FromOidcPrincipal for #name #type_generics #where_clause {
            fn from_principal(principal: ::oidc_middleware::Principal) -> Self {
                Self { #(#initializers),* }
            }
        }

        impl #request_impl_generics ::axum::extract::FromRequestParts<S> for #name #type_generics #request_where_clause {
            type Rejection = ::oidc_middleware::Error;

            async fn from_request_parts(
                parts: &mut ::axum::http::request::Parts,
                state: &S,
            ) -> ::std::result::Result<Self, Self::Rejection> {
                let principal = ::oidc_middleware::OidcPrincipal::from_request_parts(parts, state)
                    .await?
                    .into_inner();
                Ok(<Self as ::oidc_middleware::FromOidcPrincipal>::from_principal(principal))
            }
        }
    }
}

fn expand_from_oidc_session(input: &DeriveInput) -> TokenStream2 {
    let fields = match oidc_fields(input) {
        Ok(fields) => fields,
        Err(error) => return error.to_compile_error(),
    };
    let initializers = match session_initializers(input, &fields) {
        Ok(initializers) => initializers,
        Err(error) => return error.to_compile_error(),
    };
    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();
    let mut request_generics = input.generics.clone();
    request_generics.params.push(parse_quote!(S));
    request_generics
        .make_where_clause()
        .predicates
        .push(parse_quote!(S: Send + Sync));
    let (request_impl_generics, _, request_where_clause) = request_generics.split_for_impl();

    quote! {
        impl #impl_generics ::oidc_middleware::FromOidcSession for #name #type_generics #where_clause {
            fn from_session(session: ::oidc_middleware::OidcSession) -> Self {
                Self { #(#initializers),* }
            }
        }

        impl #request_impl_generics ::axum::extract::FromRequestParts<S> for #name #type_generics #request_where_clause {
            type Rejection = ::oidc_middleware::Error;

            async fn from_request_parts(
                parts: &mut ::axum::http::request::Parts,
                state: &S,
            ) -> ::std::result::Result<Self, Self::Rejection> {
                let session = ::oidc_middleware::OidcSession::from_request_parts(parts, state).await?;
                Ok(<Self as ::oidc_middleware::FromOidcSession>::from_session(session))
            }
        }
    }
}

fn principal_initializers(
    input: &DeriveInput,
    fields: &[OidcField<'_>],
) -> syn::Result<Vec<TokenStream2>> {
    fields
        .iter()
        .map(|field| {
            let ident = field.ident;
            match &field.kind {
                OidcFieldKind::Principal => Ok(quote! { #ident: principal.clone() }),
                OidcFieldKind::Subject => Ok(quote! { #ident: principal.subject().to_owned() }),
                OidcFieldKind::IdToken | OidcFieldKind::IdTokenClaim(_) => Err(
                    syn::Error::new_spanned(
                        field.field,
                        "ID token fields require #[derive(FromOidcSession)]",
                    ),
                ),
            }
        })
        .collect::<syn::Result<Vec<_>>>()
        .and_then(|initializers| {
            if fields.iter().any(|field| matches!(field.kind, OidcFieldKind::Principal)) {
                Ok(initializers)
            } else {
                Err(syn::Error::new_spanned(
                    input,
                    "FromOidcPrincipal derive requires a field marked #[oidc(principal)] or named `principal`",
                ))
            }
        })
}

fn session_initializers(
    input: &DeriveInput,
    fields: &[OidcField<'_>],
) -> syn::Result<Vec<TokenStream2>> {
    fields
        .iter()
        .map(|field| {
            let ident = field.ident;
            match &field.kind {
                OidcFieldKind::Principal => Ok(quote! { #ident: session.principal().clone() }),
                OidcFieldKind::Subject => Ok(quote! { #ident: session.principal().subject().to_owned() }),
                OidcFieldKind::IdToken => Ok(quote! { #ident: session.id_token().cloned() }),
                OidcFieldKind::IdTokenClaim(claim) => Ok(quote! {
                    #ident: session
                        .id_token()
                        .and_then(|token| token.claim(#claim))
                        .and_then(|value| value.as_str())
                        .map(::std::string::ToString::to_string)
                }),
            }
        })
        .collect::<syn::Result<Vec<_>>>()
        .and_then(|initializers| {
            if fields.iter().any(|field| matches!(field.kind, OidcFieldKind::Principal)) {
                Ok(initializers)
            } else {
                Err(syn::Error::new_spanned(
                    input,
                    "FromOidcSession derive requires a field marked #[oidc(principal)] or named `principal`",
                ))
            }
        })
}

fn oidc_fields(input: &DeriveInput) -> syn::Result<Vec<OidcField<'_>>> {
    let Data::Struct(data) = &input.data else {
        return Err(syn::Error::new_spanned(
            input,
            "OIDC derives support named structs only",
        ));
    };
    let Fields::Named(fields) = &data.fields else {
        return Err(syn::Error::new_spanned(
            input,
            "OIDC derives support named structs only",
        ));
    };

    fields
        .named
        .iter()
        .map(|field| {
            let Some(ident) = field.ident.as_ref() else {
                return Err(syn::Error::new_spanned(
                    field,
                    "OIDC derives support named fields only",
                ));
            };
            Ok(OidcField {
                field,
                ident,
                kind: oidc_field_kind(field, ident)?,
            })
        })
        .collect()
}

fn oidc_field_kind(field: &Field, ident: &Ident) -> syn::Result<OidcFieldKind> {
    let mut kind = None;
    for attr in field
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("oidc"))
    {
        attr.parse_nested_meta(|meta| {
            let next = if meta.path.is_ident("principal") {
                OidcFieldKind::Principal
            } else if meta.path.is_ident("subject") {
                OidcFieldKind::Subject
            } else if meta.path.is_ident("id_token") {
                OidcFieldKind::IdToken
            } else if meta.path.is_ident("id_token_claim") {
                let value = meta.value()?;
                OidcFieldKind::IdTokenClaim(value.parse()?)
            } else {
                return Err(meta.error("unsupported oidc field attribute"));
            };
            if kind.is_some() {
                return Err(meta.error("only one oidc field attribute is allowed per field"));
            }
            kind = Some(next);
            Ok(())
        })?;
    }

    Ok(kind.unwrap_or_else(|| inferred_field_kind(ident)))
}

fn inferred_field_kind(ident: &Ident) -> OidcFieldKind {
    match ident.to_string().as_str() {
        "principal" => OidcFieldKind::Principal,
        "subject" | "user_id" => OidcFieldKind::Subject,
        "id_token" => OidcFieldKind::IdToken,
        name => OidcFieldKind::IdTokenClaim(LitStr::new(name, ident.span())),
    }
}
