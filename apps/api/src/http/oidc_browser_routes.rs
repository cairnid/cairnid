mod authorize_route;
mod logout_route;

pub(super) use self::{
    authorize_route::authorize,
    logout_route::{end_session, end_session_post},
};
