import requests
from bs4 import BeautifulSoup
import csv

#   URL  of the quotes website to scrap 
url = "http://quotes.toscrape.com/"

#   Send a GET request to website 
response = requests.get(url)
response.raise_for_status() #Ensure we notics bad responses

#   Parse the HTML content using BeautifulSoup
soup = BeautifulSoup (response.text, 'html.parser')

#   Open the CSV file to store the data
with open('quotes.csv' , 'w', newline='' , encoding= 'utf-8' ) as file:
    writer = csv.writer(file)
    writer.writerow(['Quotes' , 'Author' , 'Tags'])         # Write the Header now

#   Find all the quote containers
    quotes = soup.find_all('div', class_='quote')

    for quote in quotes:
        text = quote.find('span' , class_='text').get_text()
        author = quote.find("small" , class_='author').get_text()
        tags = [tag.get_text() for tag in quote.find_all('a' , class_='tag')]
        writer.writerow([text, author, ', '.join(tags)])

# Print completion message outside the loop and the 'with' block
print("Scraping completed and data stored in 'quotes.csv'")
    