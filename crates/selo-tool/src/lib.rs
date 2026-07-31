//! ZeroClaw tool plugin: `selo`.
//!
//! One component holding the whole counter: quote an item, check whether
//! it was paid, and close the day.
//!
//! Why one component
//! -----------------------------------
//! Quoting writes the append-only record of what was sold; settlement
//! reads it to decide what an arriving payment bought. If those lived in
//! separate components the record would have to travel between them as a
//! tool argument, which would put it in the model's hands. A manipulated
//! model could then assert that an order was for something it was not,
//! and settlement would have no way to know better. keeping both in one
//! instance means the log is never serialized into a place an injected
//! instruction can reach.
//!
//! worth stating: this component holds http_client` because
//! the check action reads the chain, so the quoting
//! path now runs somewhere network access exists, which is weaker
//! least-privilege than a quote-only component had. integrity of the log
//! is the more important property, since the log is what the period's books
//! are derived from.
//!
//! The security model
//! -------------------------------
//! the model selects, code constructs. The model picks which catalog item
//! a customer seems to want and which order to check on. It cannot name a
//! price, a discount, a total, a destination address, or declare that a
//! payment happened. Prices come from operator config. The receiving
//! address comes from operator config. Confirmation comes from parsed
//! chain data and nothing else
