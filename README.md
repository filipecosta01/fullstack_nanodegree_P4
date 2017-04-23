Udacity - Item Catalog - Project 4 - Filipe Costa
============

This is a front-end (HTML, CSS, front-end frameworks like Bootstrap) and back-end (Python with Jinja2) that runs on a
Virtual Machine (VM - Vagrant) project intended to provide a item catalog tool.
The item catalog only allows regular CRUD operations to create categories and items for the item catalog.
Users can create items for a category they do not own but can only edit/delete categories and items that they've created.
Users can registrate themselves using their Google's account (oAuth2).

## Libraries
This project use external library other than the ones included in Python Source Libraries.
The external libraries are:
1. flask framework
2. sqlalchemy
3. jinja2 templates

Please make sure to have it installed before moving forward.

## Running locally

Aditional instructions on how to install Vagrant and Virtual Box (MacOS ONLY) are provided below:
1. [Read a bit more about Vagrant first](https://www.vagrantup.com/intro/index.html)
2. [Installation - Virtual Box and Vagrant](http://sourabhbajaj.com/mac-setup/Vagrant/README.html)

Make sure to not add a virtual box after installing vagrant, this project already have a configuration for the specific machine
you should use to run it properly.

After the steps above, make sure to clone this project into a folder in your system. Then:
1. Open a terminal and go to `<PATH-TO-CLONED-DIRECTORY>/vagrant`
2. Run `vagrant up` and wait for a while. This command will set a new virtual box machine and install all the plugins required to run this project properly
3. After step 2 ends successfuly, run `vagrant ssh` to access your new virtual box machine
4. Run `cd /vagrant/item-catalog` to open the correct folder in your terminal

Almost there. Few more steps to start your server locally:
1. From `item-catalog` folder, run `python catalog.py` to create the catalog database
2. Run `python catalog_loader.py` to populate some of the tables (it automatically inserts content in database)
3. Run `python server.py` and check http://localhost:8000. The Catalog web page should be available if all finishes with success.

## API Endpoints
This project provides endpoints for each HTML page that has not-editable content.
The endpoints available right now are:

1. `/catalog/JSON`- The JSON with categories available and latest items created.
2. `/catalog/category/<int:category_id>/items/JSON`- The JSON with the category selected and all the items for it
3. `/catalog/category/<int:category_id>/item/<int:item_id>JSON`- The JSON with the category selected and the specific item for it

Don't forget to check the code's documentation in case of doubts.

## [Contacting the Author](mailto:s.costa.filipe@gmail.com)
Click above and feel free to get in touch in case of trouble or suggestions.