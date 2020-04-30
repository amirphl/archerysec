from django.conf.urls import url

from vulner_search.views import search_vulner, search_page

urlpatterns = [
    url('search_page', search_page, name='search_page'),
    url('search_vulner', search_vulner, name='search_vulner'),
]
