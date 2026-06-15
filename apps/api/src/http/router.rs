mod admin;
mod layers;
mod protocol;
mod scim;
mod session;

use axum::Router;

use self::{
    admin::admin_routes, layers::apply_router_layers, protocol::protocol_routes,
    scim::scim_api_routes, session::session_routes,
};
use super::AppState;

pub fn build_router(state: AppState) -> Router {
    let router = Router::new()
        .merge(protocol_routes())
        .merge(scim_api_routes())
        .merge(session_routes())
        .merge(admin_routes());

    apply_router_layers(router, &state).with_state(state)
}
