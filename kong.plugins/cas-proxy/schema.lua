return {
    no_consumer = true,
    fields = {
        cas_url = { type = "url", default = "xxx", required = true },
        login_host = { type = "url", default = "xxx", required = true },
        store_name = { type = "string", default = "cas_store" },
        session_lifetime = { type = "number", default = 3600 },
        cookie_name = { type = "string", default = "NGXCAS" },
        cookie_params = { type = "string", default = "; Path=/" },
    }
}