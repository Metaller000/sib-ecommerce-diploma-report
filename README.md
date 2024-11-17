# sib-ecommerce-diploma-report

## Отчеты
### Отчет necommerce-frontend
#### nsecure (sast и зависимосты):
[Отчет](assets/nsecure-result.json) 

#### Dependabot 98 уязвимостей
![Image alt](assets/dependabot_front_1.png "")
![Image alt](assets/dependabot_front_2.png "")
![Image alt](assets/dependabot_front_3.png "")
![Image alt](assets/dependabot_front_4.png "")

#### trivy 19 узвимостей
![Image alt](assets/trivy_front.png "")

### Отчет necommerce-backend
#### SonarQube SAST
* hight
```
1. Define a constant instead of duplicating this literal "Подборка книг" 3 times. 
    src/main/kotlin/ru/netology/necommerce/NecommerceApplication.kt
```
* medium
```
2. Do not hardcode version numbers.
    implementation("org.springframework.security:spring-security-jwt:1.1.1.RELEASE
") 
in build.gradle.kts

3. Do not hardcode version numbers.
    implementation("org.apache.tika:tika-parsers:1.25
") 
in build.gradle.kts

4. Do not hardcode version numbers.
    implementation("com.google.firebase:firebase-admin:7.0.1
") 
in build.gradle.kts

5. Remove this commented out code.
        fun runner(
        userService: UserService,
        productService: ProductService,
//        @Value("\${app.media-location}") mediaLocation: String,
    ) = CommandLineRunner {
//        ResourceUtils.getFile("classpath:static").copyRecursively(
//            ResourceUtils.getFile(mediaLocation),
//            true,
//        )
in src/main/kotlin/ru/netology/necommerce/NecommerceApplication.kt

6. Update this function so that its implementation is not identical to "likeById" on line 73 
in src/main/kotlin/ru/netology/necommerce/service/CommentService.kt
```
* low
```
7. Remove this unused import.
import org.springframework.beans.factory.annotation.Value
in src/main/kotlin/ru/netology/necommerce/NecommerceApplication.kt

8. Remove this unused import.
import org.springframework.util.ResourceUtils
in src/main/kotlin/ru/netology/necommerce/NecommerceApplication.kt

9. Remove this unused import.
import java.nio.file.Paths
in src/main/kotlin/ru/netology/necommerce/config/AppWebMvcConfigurer.kt

10. Remove this unused import.
src/main/kotlin/ru/netology/necommerce/config/AppWebSecurityConfigurerAdapter.kt
in import org.springframework.security.crypto.password.PasswordEncoder 

11. Remove this unused import.
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder 
in src/main/kotlin/ru/netology/necommerce/config/AppWebSecurityConfigurerAdapter.kt


12. Remove this unused import.
import org.springframework.web.filter.CorsFilter
in src/main/kotlin/ru/netology/necommerce/config/AppWebSecurityConfigurerAdapter.kt

13. Remove this unused import.
src/main/kotlin/ru/netology/necommerce/controller/OrderController.kt
in import ru.netology.necommerce.dto.Product

14. Remove this unused import.
src/main/kotlin/ru/netology/necommerce/controller/OrderController.kt
in import ru.netology.necommerce.service.ProductService

15. Remove this unused import.
src/main/kotlin/ru/netology/necommerce/service/ProductService.kt
in import ru.netology.necommerce.exception.PermissionDeniedException

16. Complete the task associated to this TODO comment.
in src/main/kotlin/ru/netology/necommerce/service/ScheduledTokenInvalidatorService.kt

17. Remove this unused import.
import java.security.SecureRandom
in src/main/kotlin/ru/netology/necommerce/service/UserService.kt
```

#### Secret scanning 1 уязвимость
![Image alt](assets/secret_scanning.png "")

#### trivy 296 уязвимостей
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

    SAST анализ истрментом nsecure не выявил уязвимостей.

    CVE-2023-45853 - связано с пакетом zlib1g ver: 1:1.2.13.dfsg-1, пакет содержит 
    ошибку переполнения кучи целочисленных значений, что приводит к неправильным 
    вычислением, необходимо заменить или отказаться полностью.

    CVE-2023-6879 - связано с пакетом libaom3 ver: 3.6.0-1+deb12u1, пакет может 
    привести к повреждению памяти, необходимо заменить или отказаться полностью.

    Dependabot alerts - необходимо обновить библиотеку axios до версии 0.28.0.

2. Проект necommerce-backend.

    по результатам SAST при помощи SonarQube было выявлено 17 severyty уязвимотей, 
    подробности в отчете. 

    Обнаружен секрет в файле fcm.json, необходимо удалить из проекта, сгенерировать 
    новые секреты и спрятать вне проекта, например в HashiCorp vault или сереты guthub.

    Обнаружено 53 критических уязвимости, в данном случае проще отказаться от 
    выбранного языка и переписать приложение выбрав более безопасный язык, например 
    rust.

3. Автопентест.

    Проведено сканирование при помощи ZAP в Standard Mode — обычное сканирование и ATTACK Mode — режим атаки, позволяющий, помимо сканирования, также выполнять атаки на потенциальный сайт/приложение атаки проводились на разверный локально в контейнере frontend.
    Обнаружена критическая ошибка связаная с неправильно настроенным NGIX, которая может
    приводить к раскрытию мета данных облачных сервисов из-за возможности обращаться по адресу 169.254.169.254, при развертке на них. Для исправления нужно добавить 
    проверку:    
    if ($http_host = "169.254.169.254") {
        return 403;
    }
    подробнее: https://docs.stackhawk.com/vulnerabilities/90034/    
```