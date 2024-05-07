rule InternalMonitoramentoLeak12

{   
        meta:
        author = "SeuNome"
        description = "Detecta a presença de qualquer uma das strings especificadas"
        date = "2024-03-06"

    strings:
        $string1 = "Example" nocase
        $string2 = "a" nocase


    condition:
        any of them
}
