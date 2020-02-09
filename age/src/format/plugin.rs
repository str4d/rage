use age_core::format::AgeStanza;

#[derive(Debug)]
pub(crate) struct RecipientLine {
    pub(crate) tag: String,
    pub(crate) args: Vec<String>,
    pub(crate) body: Vec<u8>,
}

impl RecipientLine {
    pub(super) fn from_stanza(stanza: AgeStanza<'_>) -> Self {
        RecipientLine {
            tag: stanza.tag.to_string(),
            args: stanza.args.into_iter().map(|s| s.to_string()).collect(),
            body: stanza.body,
        }
    }
}

pub(super) mod write {
    use age_core::format::write::age_stanza;
    use cookie_factory::{SerializeFn, WriteContext};
    use std::io::Write;

    use super::RecipientLine;

    pub(crate) fn recipient_line<'a, W: 'a + Write>(
        r: &'a RecipientLine,
    ) -> impl SerializeFn<W> + 'a {
        move |w: WriteContext<W>| {
            let args: Vec<_> = r.args.iter().map(|s| s.as_str()).collect();
            let writer = age_stanza(&r.tag, &args, &r.body);
            writer(w)
        }
    }
}
