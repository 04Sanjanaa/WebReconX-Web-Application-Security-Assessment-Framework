import pytest
from unittest.mock import patch, MagicMock
from webreconx.core.validator import TargetValidator
from webreconx.crawler.crawler import WebCrawler

@patch('requests.get')
def test_crawler_limits_and_scope(mock_get):
    # Set up mock HTML content
    # Page 1 contains a link to page 2 and an out-of-scope link
    mock_res1 = MagicMock()
    mock_res1.status_code = 200
    mock_res1.headers = {"Content-Type": "text/html"}
    mock_res1.content = b'<html><body><a href="/page2">Page 2</a><a href="https://google.com">Google</a></body></html>'
    mock_res1.text = mock_res1.content.decode()
    mock_res1.apparent_encoding = "utf-8"

    mock_res2 = MagicMock()
    mock_res2.status_code = 200
    mock_res2.headers = {"Content-Type": "text/html"}
    mock_res2.content = b'<html><body><a href="/page3">Page 3</a></body></html>'
    mock_res2.text = mock_res2.content.decode()
    mock_res2.apparent_encoding = "utf-8"

    mock_res3 = MagicMock()
    mock_res3.status_code = 200
    mock_res3.headers = {"Content-Type": "text/html"}
    mock_res3.content = b'<html><body>Finished</body></html>'
    mock_res3.text = mock_res3.content.decode()
    mock_res3.apparent_encoding = "utf-8"

    # Define mock_get behavior based on URL
    def side_effect(url, *args, **kwargs):
        if url.endswith("/page2"):
            return mock_res2
        elif url.endswith("/page3"):
            return mock_res3
        else:
            return mock_res1

    mock_get.side_effect = side_effect

    validator = TargetValidator(mode="passive")
    base_url = "http://example.com"
    
    # 1. Test Depth Limit = 1
    crawler = WebCrawler(base_url=base_url, validator=validator, max_depth=1, max_pages=10)
    pages = crawler.start()
    
    # Base page is depth 0 (crawled). Links inside base page point to /page2 (depth 1, crawled).
    # Links inside /page2 point to /page3 (depth 2, not crawled because max_depth=1).
    assert "http://example.com/" in pages
    assert "http://example.com/page2" in pages
    assert "http://example.com/page3" not in pages
    assert "https://google.com/" not in pages  # out of scope

    # 2. Test Max Pages Limit = 1
    mock_get.reset_mock()
    crawler_pages_limit = WebCrawler(base_url=base_url, validator=validator, max_depth=5, max_pages=1)
    pages_limited = crawler_pages_limit.start()
    assert len(pages_limited) == 1

@patch('requests.get')
def test_crawler_duplicate_prevention(mock_get):
    mock_res = MagicMock()
    mock_res.status_code = 200
    mock_res.headers = {"Content-Type": "text/html"}
    mock_res.content = b'<html><body><a href="/page2">Page 2</a><a href="/page2/">Page 2 slash</a><a href="/page2?q=1">Page 2 q</a></body></html>'
    mock_res.text = mock_res.content.decode()
    mock_res.apparent_encoding = "utf-8"

    mock_get.return_value = mock_res

    validator = TargetValidator()
    crawler = WebCrawler("http://example.com/", validator=validator, max_depth=2, max_pages=10)
    pages = crawler.start()
    
    assert "http://example.com/" in pages
    assert "http://example.com/page2" in pages
    assert mock_get.call_count <= 3

@patch('requests.get')
def test_crawler_redirect_out_of_scope(mock_get):
    mock_res = MagicMock()
    mock_res.status_code = 302
    mock_res.headers = {"Location": "http://google.com/"}
    mock_res.content = b""
    mock_res.text = ""
    
    mock_get.return_value = mock_res

    validator = TargetValidator()
    crawler = WebCrawler("http://example.com/", validator=validator, max_depth=2, max_pages=10)
    
    page_data = crawler.crawl_page("http://example.com/redirects", 0)
    
    assert page_data is not None
    assert "http://google.com/" in page_data["redirects"]
    assert page_data["final_url"] == "http://example.com/redirects"

@patch('requests.get')
def test_crawler_timeout_handling(mock_get):
    import requests
    mock_get.side_effect = requests.exceptions.Timeout("Connection timed out")
    
    validator = TargetValidator()
    crawler = WebCrawler("http://example.com/", validator=validator)
    
    page_data = crawler.crawl_page("http://example.com/timeout", 0)
    assert page_data is None
