
from selenium import webdriver



class Requests_browser():
    def __init__(self,headers=0,loadimg = False):
        default_headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 '
                                      '(KHTML, like Gecko) Chrome/38.0.2125.111 Safari/537.36 BBScan/1.1'}
        cap = webdriver.DesiredCapabilities.PHANTOMJS
        cap['phantomjs.page.settings.loadImages'] = loadimg

        if headers:
            for key, value in enumerate(headers):
                cap['phantomjs.page.customHeaders.{}'.format(key)] = value
        else:
            for key, value in enumerate(default_headers):
                cap['phantomjs.page.customHeaders.{}'.format(key)] = value
        self.driver = webdriver.PhantomJS(desired_capabilities=cap)

    def get(self,url,cookies={}):
        driver = self.driver
        for cookie in cookies:
            driver.add_cookie({k: cookie[k] for k in ('name', 'value', 'domain', 'path', 'expiry')})
        driver.get(url)
        return driver.page_source
