idf_component_register(
    SRCS
        "sd_logger_core.c"
        "sd_logger_idf.c"
    INCLUDE_DIRS "include"
    PRIV_REQUIRES
        board
        radio
        console
        esp_timer
        esp_system
        heap
        fatfs
)
