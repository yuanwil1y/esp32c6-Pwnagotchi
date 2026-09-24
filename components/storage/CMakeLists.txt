idf_component_register(
    SRCS
        "capture_serial_protocol.c"
        "sd_logger_core.c"
        "sd_logger_idf.c"
    INCLUDE_DIRS "include"
    PRIV_REQUIRES
        board
        radio
        esp_driver_usb_serial_jtag
        esp_timer
        esp_system
        heap
        fatfs
)
