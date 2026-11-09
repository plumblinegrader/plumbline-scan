class Rectangle:
    def __init__(self, width, height):
        self.width = width
        self.height = height

    def area(self):
        computed_area = self.width * self.height
        assert computed_area >= 0, "negative dimensions"
        return computed_area
