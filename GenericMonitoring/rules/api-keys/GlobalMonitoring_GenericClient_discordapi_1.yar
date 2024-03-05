rule GlobalMonitoring_GenericClient_discordapi_1
{
    meta:
        author = "@ntddk"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $a = "DiscordRelay.BotToken" nocase
        $b = "discordapp.com/api/webhooks" nocase
    condition:
        any of them
}
