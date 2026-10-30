//! A user's chosen skin is remembered against their account, and the value the
//! client sends is validated before it is stored.
//!
//! Per user rather than per browser is the point of "remembered": an examiner
//! who has set up a workstation they can read should not have to do it again on
//! the second machine in the lab, or after clearing site data.
//!
//! The validation matters because this is a string a client chooses and the
//! server hands back to every session that user opens. What the server is
//! answerable for is that it is bounded and shaped like a name; which skins
//! exist is the frontend's knowledge, and a server holding that list too would
//! need a redeploy to add one.

use anyhow::Result;
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;

async fn setup() -> Result<(SqliteConnection, uuid::Uuid)> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    let id = db
        .create_user("ivy", "$2b$04$notarealhash", "examiner")
        .await?;
    Ok((db, id))
}

#[tokio::test]
async fn a_new_user_has_chosen_nothing() -> Result<()> {
    let (db, _) = setup().await?;
    // Distinct from having chosen the default. "I never chose" follows whatever
    // this build ships; "I chose the one that is currently the default" stays
    // put if the default ever moves.
    assert_eq!(db.get_user_theme("ivy").await?, None);
    Ok(())
}

#[tokio::test]
async fn a_chosen_theme_is_remembered_and_can_be_cleared() -> Result<()> {
    let (db, id) = setup().await?;

    assert!(db.set_user_theme(id, Some("nature:light")).await?);
    assert_eq!(
        db.get_user_theme("ivy").await?.as_deref(),
        Some("nature:light")
    );

    assert!(db.set_user_theme(id, Some("cyber:dark")).await?);
    assert_eq!(
        db.get_user_theme("ivy").await?.as_deref(),
        Some("cyber:dark")
    );

    assert!(db.set_user_theme(id, None).await?);
    assert_eq!(db.get_user_theme("ivy").await?, None);
    Ok(())
}

#[tokio::test]
async fn one_users_theme_is_not_another_users() -> Result<()> {
    let (db, ivy) = setup().await?;
    let jack = db
        .create_user("jack", "$2b$04$notarealhash", "examiner")
        .await?;

    db.set_user_theme(ivy, Some("relax:dark")).await?;
    db.set_user_theme(jack, Some("win11:light")).await?;

    assert_eq!(
        db.get_user_theme("ivy").await?.as_deref(),
        Some("relax:dark")
    );
    assert_eq!(
        db.get_user_theme("jack").await?.as_deref(),
        Some("win11:light")
    );
    Ok(())
}

#[tokio::test]
async fn a_theme_for_a_user_who_does_not_exist_changes_nothing() -> Result<()> {
    let (db, _) = setup().await?;
    // `false` rather than an error, so the API can answer 404 instead of
    // reporting a success it did not have.
    assert!(
        !db.set_user_theme(uuid::Uuid::new_v4(), Some("opus:dark"))
            .await?
    );
    Ok(())
}

#[tokio::test]
async fn only_something_shaped_like_a_theme_name_is_stored() -> Result<()> {
    let (db, id) = setup().await?;
    db.set_user_theme(id, Some("opus:dark")).await?;

    let refused = [
        // Not a mode.
        "opus:sideways",
        "opus:",
        // No mode at all.
        "opus",
        "",
        // Not a skin name: uppercase, spaces, punctuation, path traversal, a
        // script fragment, a quote that would matter if this were ever
        // interpolated rather than bound.
        "Opus:dark",
        "op us:dark",
        "../../etc/passwd:dark",
        "<script>:dark",
        "opus';--:dark",
        // Unbounded. This is the one that matters most: the value is echoed
        // back to every session the user opens.
        "opus:dark:extra",
    ];
    for value in refused {
        assert!(
            db.set_user_theme(id, Some(value)).await.is_err(),
            "{value:?} must be refused"
        );
    }

    let long = format!("{}:dark", "a".repeat(33));
    assert!(
        db.set_user_theme(id, Some(&long)).await.is_err(),
        "a skin name over 32 characters must be refused"
    );

    // And the refusals changed nothing: the theme that was there is still there.
    assert_eq!(
        db.get_user_theme("ivy").await?.as_deref(),
        Some("opus:dark")
    );
    Ok(())
}

#[tokio::test]
async fn a_skin_this_server_has_never_heard_of_is_accepted() -> Result<()> {
    let (db, id) = setup().await?;
    // Deliberate. The catalogue of skins lives in the frontend, which holds the
    // palettes; a server that also held it would reject a newer client's
    // perfectly good choice until it was redeployed. A client that reads back a
    // skin it does not recognise falls back to the default, which is the same
    // thing it does for a user who never chose.
    assert!(db.set_user_theme(id, Some("solarized-2029:light")).await?);
    assert_eq!(
        db.get_user_theme("ivy").await?.as_deref(),
        Some("solarized-2029:light")
    );
    Ok(())
}
