import sys

from sqlalchemy import Column, ForeignKey, Integer, String, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref
from sqlalchemy import create_engine
from sqlalchemy.sql import func

Base = declarative_base()

class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key = True)
    name = Column(String(80), nullable = False)
    email = Column(String(80), nullable = False)

class Category(Base):
    __tablename__ = 'category'
    items = []

    id = Column(Integer, primary_key = True)
    title = Column(String(80), nullable = False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'title': self.title,
            'items': self.items
        }

class Item(Base):
    __tablename__ = 'item'

    id = Column(Integer, primary_key = True)
    title = Column(String(80), nullable = False)
    description = Column(Text, nullable = False)
    category_id = Column(Integer, ForeignKey('category.id'))
    created_at = Column(DateTime(timezone=True), default=func.now())
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    category = relationship(Category, backref=backref('items', uselist=True,
                                                      cascade='delete,all'))

    @property
    def serialize(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'category_id': self.category_id,
            'created_at': self.created_at
        }


engine = create_engine('sqlite:///catalog.db')

Base.metadata.create_all(engine)