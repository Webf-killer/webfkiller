import subprocess
from bs4 import BeautifulSoup

def test_for_syntax_errors_in_script(script_text):
    soup = BeautifulSoup(script_text, 'html.parser')
    script_tags = soup.find_all('script')

    for script in script_tags:
        script_code = script.get_text()
        if script_code.strip():
            try:
                # Node.js를 사용하여 스크립트 코드를 실행
                process = subprocess.run(['node', '-e', script_code], check=True, capture_output=True, text=True)
            except subprocess.CalledProcessError as e:
                # Node.js 실행 중 에러 발생 (구문 오류 포함)
                print(f"Error detected in script: {script_code}")
                print(e.output)
                return True
    return False

# 사용 예시
script_text = """
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">

<html xmlns="http://www.w3.org/1999/xhtml">

        <head>
                <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />

                <title>Vulnerability: Reflected Cross Site Scripting (XSS) :: Damn Vulnerable Web Application (DVWA) v1.10 *Development*</title>

                <link rel="stylesheet" type="text/css" href="../../dvwa/css/main.css" />

                <link rel="icon" type="\image/ico" href="../../favicon.ico" />

                <script type="text/javascript" src="../../dvwa/js/dvwaPage.js"></script>

        </head>

        <body class="home">
                <div id="container">

                        <div id="header">

                                <img src="../../dvwa/images/logo.png" alt="Damn Vulnerable Web Application" />

                        </div>

                        <div id="main_menu">

                                <div id="main_menu_padded">
                                <ul class="menuBlocks"><li class=""><a href="../../.">Home</a></li>
<li class=""><a href="../../instructions.php">Instructions</a></li>
<li class=""><a href="../../setup.php">Setup / Reset DB</a></li>
</ul><ul class="menuBlocks"><li class=""><a href="../../vulnerabilities/brute/">Brute Force</a></li>
<li class=""><a href="../../vulnerabilities/exec/">Command Injection</a></li>
<li class=""><a href="../../vulnerabilities/csrf/">CSRF</a></li>
<li class=""><a href="../../vulnerabilities/fi/.?page=include.php">File Inclusion</a></li>
<li class=""><a href="../../vulnerabilities/upload/">File Upload</a></li>
<li class=""><a href="../../vulnerabilities/captcha/">Insecure CAPTCHA</a></li>
<li class=""><a href="../../vulnerabilities/sqli/">SQL Injection</a></li>
<li class=""><a href="../../vulnerabilities/sqli_blind/">SQL Injection (Blind)</a></li>
<li class=""><a href="../../vulnerabilities/weak_id/">Weak Session IDs</a></li>
<li class=""><a href="../../vulnerabilities/xss_d/">XSS (DOM)</a></li>
<li class="selected"><a href="../../vulnerabilities/xss_r/">XSS (Reflected)</a></li>
<li class=""><a href="../../vulnerabilities/xss_s/">XSS (Stored)</a></li>
<li class=""><a href="../../vulnerabilities/csp/">CSP Bypass</a></li>
<li class=""><a href="../../vulnerabilities/javascript/">JavaScript</a></li>
</ul><ul class="menuBlocks"><li class=""><a href="../../security.php">DVWA Security</a></li>
<li class=""><a href="../../phpinfo.php">PHP Info</a></li>
<li class=""><a href="../../about.php">About</a></li>
</ul><ul class="menuBlocks"><li class=""><a href="../../logout.php">Logout</a></li>
</ul>
                                </div>

                        </div>

                        <div id="main_body">


<div class="body_padded">
        <h1>Vulnerability: Reflected Cross Site Scripting (XSS)</h1>

        <div class="vulnerable_code_area">
                <form name="XSS" action="#" method="GET">
                        <p>
                                What's your name?
                                <input type="text" name="name">
                                <input type="submit" value="Submit">
                        </p>

                </form>
                <pre>Hello <script>var a = "AAAAAAAA'"";</script></pre>
        </div>

        <h2>More Information</h2>
        <ul>
                <li><a href="https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)" target="_blank">https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)</a></li>
                <li><a href="https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet" target="_blank">https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet</a></li>
                <li><a href="https://en.wikipedia.org/wiki/Cross-site_scripting" target="_blank">https://en.wikipedia.org/wiki/Cross-site_scripting</a></li>
                <li><a href="http://www.cgisecurity.com/xss-faq.html" target="_blank">http://www.cgisecurity.com/xss-faq.html</a></li>
                <li><a href="http://www.scriptalert1.com/" target="_blank">http://www.scriptalert1.com/</a></li>
        </ul>
</div>

                                <br /><br />


                        </div>

                        <div class="clear">
                        </div>

                        <div id="system_info">
                                <input type="button" value="View Help" class="popup_button" id='help_button' data-help-url='../../vulnerabilities/view_help.php?id=xss_r&security=low' )"> <input type="button" value="View Source" class="popup_button" id='source_button' data-source-url='../../vulnerabilities/view_source.php?id=xss_r&security=low' )"> <div align="left"><em>Username:</em> admin<br /><em>Security Level:</em> low<br /><em>PHPIDS:</em> disabled</div>
                        </div>

                        <div id="footer">

                                <p>Damn Vulnerable Web Application (DVWA) v1.10 *Development*</p>
                                <script src='/dvwa/js/add_event_listeners.js'></script>

                        </div>

                </div>

        </body>

</html>
"""

if test_for_syntax_errors_in_script(script_text):
    print("SyntaxError detected in the provided script text.")
else:
    print("No SyntaxError detected in the script text.")