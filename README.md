# sib-ecommerce-diploma-report

## Отчеты
### Отчет necommerce-frontend
#### Dependabot
![Image alt](assets/dependabot_front_1.png "")
![Image alt](assets/dependabot_front_2.png "")
![Image alt](assets/dependabot_front_3.png "")
![Image alt](assets/dependabot_front_4.png "")

#### trivy
![Image alt](assets/trivy_front.png "")

### Отчет necommerce-backend
#### Secret scanning
![Image alt](assets/secret_scanning.png "")

#### trivy
![Image alt](assets/trivy_back_1.png "")
![Image alt](assets/trivy_back_2.png "")
![Image alt](assets/trivy_back_3.png "")
![Image alt](assets/trivy_back_4.png "")
![Image alt](assets/trivy_back_5.png "")
![Image alt](assets/trivy_back_6.png "")
![Image alt](assets/trivy_back_7.png "")
![Image alt](assets/trivy_back_8.png "")
![Image alt](assets/trivy_back_9.png "")
![Image alt](assets/trivy_back_10.png "")
![Image alt](assets/trivy_back_11.png "")
![Image alt](assets/trivy_back_12.png "")

### Отчет автопентеста
[Отчет ZAP](assets/2024-11-12-ZAP-Report-.md) 

## Рекомендации по улучшению процесса
```
После проведенного анализа были выявлены критические уязвимости которые необходимо исправить в кратчайшие сроки и потенциальные. 
Потенциальные приведены в отчетах.

Меры по устранению критических ошибок:

1. Проект necommerce-frontend.

    Не работает ossar-analysis выдает ошибку: ESLint completed with exit code 1.
    фактически не работатет статистический анализ кода на уязвимости, необходимо
    заменить иструмент, github/ossar-action@v1 использует node12 находящийся в статусе 
    deprecated что может приводит к ошибке.

    CVE-2023-45853 - связано с пакетом zlib1g ver: 1:1.2.13.dfsg-1, пакет содержит 
    ошибку переполнения кучи целочисленных значений, что приводит к неправильным 
    вычислением, необходимо заменить или отказаться полностью.

    CVE-2023-6879 - связано с пакетом libaom3 ver: 3.6.0-1+deb12u1, пакет может 
    привести к повреждению памяти, необходимо заменить или отказаться полностью.

    Dependabot alerts - выявлено множество библиотек содержащих критические уязвимости 
    и требужщих обновления: immer, @babel/traverse, minimist, loader-utils, hell-quote, 
    eventsource, ejs, url-parse, json-schema.

2. Проект necommerce-backend.

    Обнаружен секрет в файле fcm.json, необходимо удалить из проекта, сгенерировать 
    новые секреты и спрятать вне проекта, например в HashiCorp vault или сереты guthub.

    Обнаружено 53 критических уязвимости, в данном случае проще отказаться от 
    выбранного языка и переписать приложение выбрав более безопасный язык, например 
    rust.

3. Автопентест.

    Обнаружена критическая ошибка связаная с неправильно настроенным NGIX, которая может
    приводить к раскрытию мета данных облачных сервисов, для исправления нужно добавить 
    проверку:    
    if ($http_host = "169.254.169.254") {
        return 403;
    }
```