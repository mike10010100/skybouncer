//! Multi-tenant hosted service registry managing dynamic user enrollment and DPoP sessions.
//!
//! Provides [`TenantRegistry`] and [`Tenant`] for managing multi-user ATProto OAuth sessions,
//! personalized moderation rubrics, and dynamic PDS mutator client resolution.

pub mod registry;

pub use registry::{Tenant, TenantRegistry};
