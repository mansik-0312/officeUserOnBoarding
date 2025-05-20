from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response

class CustomTermsPagination(PageNumberPagination):
    page_size = 5
    page_size_query_param = 'page_size'
    max_page_size = 50

    def get_paginated_response(self, data):
        return Response({
            'page': self.page.number,
            'total_pages': self.page.paginator.num_pages,
            'total_terms': self.page.paginator.count,
            'has_next': self.page.has_next(),
            'has_previous': self.page.has_previous(),
            'results': data
        })