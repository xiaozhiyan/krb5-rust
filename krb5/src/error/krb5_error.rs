use super::{error, Error};

impl Error {
    error!(
        KRB5_PARSE_MALFORMED,
        -1765328250, "Malformed representation of principal"
    );
    error!(
        KRB5_CC_UNKNOWN_TYPE,
        -1765328244, "Unknown credential cache type"
    );
    error!(KRB5_KT_UNKNOWN_TYPE, -1765328204, "Unknown Key table type");
    error!(KRB5_FCC_NOFILE, -1765328189, "No credentials cache found");
    error!(
        KRB5_CC_FORMAT,
        -1765328185, "Bad format in credentials cache"
    );
    error!(
        KRB5_CCACHE_BADVNO,
        -1765328172, "Unsupported credentials cache format version number"
    );
    error!(
        KRB5_KEYTAB_BADVNO,
        -1765328171, "Unsupported key table format version number"
    );
    error!(
        KRB5_CONFIG_NODEFREALM,
        -1765328160, "Configuration file does not specify default realm"
    );
    error!(KRB5_KT_NAME_TOOLONG, -1765328155, "Keytab name too long");
    error!(KRB5_KT_FORMAT, -1765328149, "Bad format in keytab");
}
