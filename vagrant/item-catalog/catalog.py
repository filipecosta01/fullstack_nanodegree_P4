import sys

from sqlalchemy import Column, ForeignKey, Integer, String, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
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

    id = Column(Integer, primary_key = True)
    title = Column(String(80), nullable = False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

class Item(Base):
    __tablename__ = 'item'

    id = Column(Integer, primary_key = True)
    title = Column(String(80), nullable = False)
    description = Column(Text, nullable = False)
    category_id = Column(Integer, ForeignKey('category.id'))
    created_at = Column(DateTime(timezone=True), default=func.now())
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    category = relationship(Category)


engine = create_engine('sqlite:///catalog.db')

Base.metadata.create_all(engine)