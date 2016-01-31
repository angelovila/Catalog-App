What

  App allows user to add items and categorize them to make them browseable using a web browser


Configuration:

  App was developed and tested using the following technologies:
    - Git(Windows) - http://git-scm.com/downloads
    - VirtualBox - https://www.virtualbox.org/wiki/Downloads
    - Vagrant - https://www.vagrantup.com/downloads
    - Python 2 - https://www.python.org/downloads/

  Running the Virtual Machine:
    1. install all programs above are installed in your system
    2. using Unix terminal, go to the App's directory (see Installation/Running on where the catalog.zip is extracted)
    example: type "cd directory/AppDirectory"
    2. type "vagrant up" on the command line to launch virtual machine
    3. type "vagrant ssh" to log into the virtual machine




  Installation/Running:

  1. extract catalog.zip into it's own folder
  2. using a Unix terminal, run database_setup.py using Python. - python database_setup.py
  3. using a UNix terminal, run catalog.py using Python - python catalog.py
  4. using a web browser, enter in the url bar - localhost:8000


How To:

  Once the App is running  using a web browser, user will be able to create a category, create a product, view existing category/product

  URLS and what it's for:

    / - homepage, view of all the categories and recently added products

    /catalog/create-category/ - creating a category

    /catalog/create-product/ - creating a product

    /catalog/[category_name]/[category_id]/ - view of all the products in a category

    /catalog/[category_id]/[product_name]/[product_id] - view of a specific product


    JSON endpoints:

      add "JSON" at the end of the category or a product view to see data in a JSON format
        examples: 
         
          /catalog/[category_id]/[product_name]/[product_id]/JSON - list of products in a category in JSON
      
          /catalog/[category_name]/[category_id]/JSON - product information in JSON




BUG:
  If user is using a later version of Flask, user might encounter the following error:
      TypeError: <oauth2client.client.OAuth2Credentials object ...> is not JSON serializable

  To fix this issue, user would need to install Flask version 0.9 by typing the command below using a unix terminal.
       pip install Flask==0.9


       
