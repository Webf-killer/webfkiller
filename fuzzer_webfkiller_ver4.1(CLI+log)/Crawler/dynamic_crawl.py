from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup as bs
import requests
from urllib.parse import urljoin
import os

class Crawler:
    def __init__(self, start_url, depth, use_selenium=False):
        self.start_url = start_url
        self.depth = depth
        self.visited = set()
        # 현재 디렉토리에 결과물 생성
        current_dir = os.path.dirname(os.path.abspath(__file__))
        self.output_file = os.path.join(current_dir, 'crawl_urls.txt')
        self.use_selenium = use_selenium
        if use_selenium:
            self.driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()))

    # 페이지의 HTML data 가져오기
    def fetch_page(self, url):
        try:
            if self.use_selenium:
                self.driver.get(url)
                return self.driver.page_source
            else:
                response = requests.get(url)
                if response.status_code == 200:
                    return response.text
        
        except Exception as e:
            print(f"Error fetching page : {e}")
        return None
    
    # url을 추출하는 메서드 (a href 태그 검사 후 절대경로로 저장)
    def extract_links(self, html, base_url):
        soup = bs(html, 'html.parser')
        links = soup.find_all('a', href=True)
        return [urljoin(base_url, link['href']) for link in links]
    
    # 크롤링하는 메서드
    def crawl(self, url, current_depth=0):
        if current_depth > self.depth or url in self.visited:
            return
        
        # 방문한 url은 visited에 저장하고 출력
        self.visited.add(url)
        print(url)

        # URL 파일에 기록
        with open(self.output_file, 'a') as file:
            file.write(url + '\n')  # URL을 파일에 쓰기
        
        # 페이지 내용 가져오기
        page_content = self.fetch_page(url)
        if not page_content:
            return
        
        # url 추출 & 재귀 호출
        links = self.extract_links(page_content, url)
        for link in set(links) - self.visited:
            self.crawl(link, current_depth + 1)
        
    def close(self):
        if self.use_selenium:
            self.driver.quit()
            
if __name__ == '__main__':
    start_url = input("Start URL for crawling : ")
    depth = int(input("Crawling depth : "))
    use_selenium = input("Use Selenium? (yes/no) : ").lower() == 'yes'
    
    crawler = Crawler(start_url=start_url, depth=depth, use_selenium=use_selenium)
    crawler.crawl(start_url)
    crawler.close() # web driver때문에 꼭 닫아줘야함