"""
Pagination classes for Neubit PSIM Core Platform Service.

This module provides standardized pagination for the REST API,
ensuring consistent pagination behavior across all endpoints.
"""

from collections import OrderedDict

from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response


class StandardResultsSetPagination(PageNumberPagination):
    """
    Standard pagination class for the Core Platform API.

    This pagination class provides:
    - Page-based pagination with configurable page size
    - Consistent response format
    - Metadata about pagination state
    - Support for client-specified page sizes
    """

    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100
    page_query_param = 'page'

    def get_paginated_response(self, data):
        """
        Return a paginated response with standardized format.

        Args:
            data: The paginated data to return

        Returns:
            Response with pagination metadata and data
        """
        return Response(OrderedDict([
            ('success', True),
            ('data', OrderedDict([
                ('results', data),
                ('pagination', OrderedDict([
                    ('count', self.page.paginator.count),
                    ('page', self.page.number),
                    ('page_size', self.get_page_size(self.request)),
                    ('total_pages', self.page.paginator.num_pages),
                    ('has_next', self.page.has_next()),
                    ('has_previous', self.page.has_previous()),
                    ('next', self.get_next_link()),
                    ('previous', self.get_previous_link()),
                ]))
            ])),
            ('message', f'Retrieved {len(data)} items successfully'),
        ]))

    def get_page_size(self, request):
        """
        Get the page size for the current request.

        Args:
            request: The HTTP request object

        Returns:
            Integer page size
        """
        if self.page_size_query_param:
            try:
                page_size = int(request.query_params[self.page_size_query_param])
                if page_size > 0:
                    return min(page_size, self.max_page_size)
            except (KeyError, ValueError):
                pass

        return self.page_size


class LargeResultsSetPagination(PageNumberPagination):
    """
    Pagination class for endpoints that return large datasets.

    This pagination class is designed for endpoints that typically
    return large amounts of data, such as logs or analytics data.
    """

    page_size = 50
    page_size_query_param = 'page_size'
    max_page_size = 1000
    page_query_param = 'page'

    def get_paginated_response(self, data):
        """
        Return a paginated response for large datasets.

        Args:
            data: The paginated data to return

        Returns:
            Response with pagination metadata and data
        """
        return Response(OrderedDict([
            ('success', True),
            ('data', OrderedDict([
                ('results', data),
                ('pagination', OrderedDict([
                    ('count', self.page.paginator.count),
                    ('page', self.page.number),
                    ('page_size', self.get_page_size(self.request)),
                    ('total_pages', self.page.paginator.num_pages),
                    ('has_next', self.page.has_next()),
                    ('has_previous', self.page.has_previous()),
                    ('next', self.get_next_link()),
                    ('previous', self.get_previous_link()),
                ]))
            ])),
            ('message', f'Retrieved {len(data)} items from large dataset'),
        ]))


class SmallResultsSetPagination(PageNumberPagination):
    """
    Pagination class for endpoints that return small datasets.

    This pagination class is designed for endpoints that typically
    return small amounts of data, such as configuration or settings.
    """

    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 50
    page_query_param = 'page'

    def get_paginated_response(self, data):
        """
        Return a paginated response for small datasets.

        Args:
            data: The paginated data to return

        Returns:
            Response with pagination metadata and data
        """
        return Response(OrderedDict([
            ('success', True),
            ('data', OrderedDict([
                ('results', data),
                ('pagination', OrderedDict([
                    ('count', self.page.paginator.count),
                    ('page', self.page.number),
                    ('page_size', self.get_page_size(self.request)),
                    ('total_pages', self.page.paginator.num_pages),
                    ('has_next', self.page.has_next()),
                    ('has_previous', self.page.has_previous()),
                    ('next', self.get_next_link()),
                    ('previous', self.get_previous_link()),
                ]))
            ])),
            ('message', f'Retrieved {len(data)} items successfully'),
        ]))


def get_pagination_class(pagination_type: str = 'standard') -> PageNumberPagination:
    """
    Factory function to get the appropriate pagination class.

    Args:
        pagination_type: Type of pagination ('standard', 'large', 'small')

    Returns:
        Pagination class instance
    """
    pagination_classes = {
        'standard': StandardResultsSetPagination,
        'large': LargeResultsSetPagination,
        'small': SmallResultsSetPagination,
    }

    pagination_class = pagination_classes.get(pagination_type, StandardResultsSetPagination)
    return pagination_class()
