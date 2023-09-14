export function getParametersData () {
    const param = {
        APP_PORT: process.env.APP_PORT,
        HEADER_EVENT: process.env.HEADER_EVENT,
        HEADER_CONTENT_TYPE: process.env.HEADER_CONTENT_TYPE,
        GH_ACTION: process.env.GH_ACTION,
        GH_STATE: process.env.GH_STATE,
        GH_EVENT: process.env.GH_HEADER_EVENT,
        GH_CONTENT_TYPE: process.env.GH_HEADER_CONTENT_TYPE,
        GH_BASE: process.env.GH_BASE,
        GH_MERGED: process.env.GH_MERGED,
        GH_PREFIX_FILE: process.env.GH_PREFIX_FILE,
        BOM_PREFIX_FILE: process.env.BOM_PREFIX_FILE,
        STR_SEPARATOR: process.env.STR_SEPARATOR,
        JSON_EXTENSION: process.env.JSON_EXTENSION,
        CMD_SBOM: process.env.CMD_SBOM,
        CMD_SBOM_TIMEOUT: process.env.CMD_SBOM_TIMEOUT,
        DTRACK_API_URL: process.env.DTRACK_API_URL,
        DTRACK_API_KEY: process.env.DTRACK_API_KEY,
        APP_DEBUG: process.env.APP_DEBUG,
        MOD_W_RCV_GH_ENABLED: process.env.MOD_W_RCV_GH_ENABLED,
        MOD_DTRACK_ENABLED: process.env.MOD_DTRACK_ENABLED,
        DSABOT_SKIP_REPO: process.env.DSABOT_SKIP_REPO
        // AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID,
        // AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY,
        // AWS_REGION: process.env.AWS_REGION,
        // AWS_S3_SBOM: process.env.AWS_S3_SBOM,
        // AWS_S3_SBOM_PATH: process.env.AWS_S3_SBOM_PATH,
        // MOD_AWS_S3_ENABLED: process.env.MOD_AWS_S3_ENABLED,
    };
    return param;
}