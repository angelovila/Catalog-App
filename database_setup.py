
#configuration
import datetime  # this is for dateadded column on Items class
import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, DateTime, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class Users(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(300))
    picture = Column(String(300))


class Items(Base):  #class
    __tablename__ = 'items'  #table

    id = Column(Integer, primary_key=True)  #mapper
    name = Column(String(250), nullable=False)
    description = Column(String(300), nullable=True)
    categoryID = Column(Integer, ForeignKey('categories.id'))
    dateadded = Column(DateTime, default = datetime.datetime.utcnow)
    user_id = Column(Integer, ForeignKey('users.id'))
    image = Column(String(250))
    users = relationship(Users)




#this is to serializeablee function to be able to send JSON objects
#in serializeable format
    @property
    def serialize(self):
        return {
            'name'         : self.name,
            'description'         : self.description,
            'categoryID'         : self.categoryID,
        }



class Categories(Base):  #class
    __tablename__ = 'categories'  #table

    name = Column(String(80), nullable=False)  #mapper
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    users = relationship(Users)
    items = relationship(Items, cascade="save-update, merge, delete")
    @property
    def serialize(self):
        return {
            'name'         : self.name,
            'id'         : self.id,
            
        }

#configuration
engine = create_engine('sqlite:///Catalogs.db')


Base.metadata.create_all(engine)
