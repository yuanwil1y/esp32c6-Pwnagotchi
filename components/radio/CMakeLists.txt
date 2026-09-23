idf_component_register(
    SRCS
        "wifi_sniffer.c"
        "ieee80211_parser.c"
        "channel_hopper.c"
    INCLUDE_DIRS "include"
    PRIV_REQUIRES
        esp_wifi
        nvs_flash
        esp_netif
        esp_event
        esp_system
        esp_timer
)
