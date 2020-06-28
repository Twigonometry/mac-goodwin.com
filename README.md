# mac-goodwin.com
The code for my personal website. Developed in [Jekyll](https://jekyllrb.com/), and hosted with [Netlify](https://www.netlify.com/)

## Setup

To host this website locally, follow these steps

**Clone this repository:**

`git clone git@github.com:Twigonometry/mac-goodwin.com.git`

**Install Jekyll:**

`gem install bundler jekyll`

**Navigate to website folder:**

`cd mac-goodwin.com\mac-goodwin`

**Launch Server:**

Make sure you are in the *mac-goodwin* directory when you do this, not the parent directory *mac-goodwin&#46;com* !

`bundle exec jekyll serve`

**Navigate to site in browser**

Site is hosted at the following address by default - Jekyll will tell you if this is different when you run `jekyll serve`

`http://localhost:4000`

## Website Code

All code stored within mac-goodwin directory

*_site* and *jekyll-cache* directories are excluded by gitignore - these will be generated locally when running `jekyll serve`

### _includes

Content to be included in pages. Similar to partials in Rails

### _layouts

Liquid page templates. Can contain liquid logic as well as objects

### _posts

Content for blog posts

### assets

*css* directory contains *styles.scss*, which serves as the main stylesheet for the site

### _sass

Stylesheets for site, to be imported into *styles.scss*

## Useful Links

This markdown file contains a list of articles, posts, and questions I've used while developing the site. They serve as both a reference for me, and as some insight into my thought process as this project develops!