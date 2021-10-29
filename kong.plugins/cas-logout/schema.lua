return {
    no_consumer = true,
    fields = {
        cas_url = {type = "url", required = true},
        store_name = {type = "string", default = "cas_store" },
        cookie_name = {type = "string", default = "NGXCAS" },
        cookie_params = {type = "string", default = "; Path=/" },
    }
}