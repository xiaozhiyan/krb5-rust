use super::{error, Error};

error!(KRB5_KT_UNKNOWN_TYPE, -1765328204, "Unknown Key table type");
error!(
    KRB5_KEYTAB_BADVNO,
    -1765328171, "Unsupported key table format version number"
);
error!(KRB5_KT_NAME_TOOLONG, -1765328155, "Keytab name too long");
