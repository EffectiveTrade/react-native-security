У этого проекта есть клон - security библиотека проекта GI.
При внесении изменений в этот проект надо уведомить руководителя проекта и технической группы проекта GI о необходимости рассмотреть внесение аналогичных исправлений.

Если вы делаете форк от этого проекта, вам, помимо переименования очевидных имен (пакеты, префиксы и т.д.), необходимо задать уникальные значения имен сервисов для sskeychain в /ios/VBNativeAuth/VBNativeAuth.m

```
NSString *const CredServiceLogin = ...;
NSString *const CredServicePassword = ...;
NSString *const CredServiceBiometry = ...;
NSString *const CredServiceAttemptCounter = ...;
```