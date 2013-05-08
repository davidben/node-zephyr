{
    "targets": [
        {
            "target_name": "zephyr",
            "sources": [ "src/zephyr.cc", "src/utf8proc.c" ],
            "link_settings": {
                "libraries": [
                    "-lzephyr"
                ]
            },
            "cflags": [
                "-W", "-Wall", "-Wno-unused-parameter"
            ]
        }
    ]
}
