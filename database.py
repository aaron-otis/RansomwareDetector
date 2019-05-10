import pymongo
from abc import ABC, abstractmethod


class Database(ABC):
    """Abstract database class."""
    def __init__(self):
        super(Database, self).__init__()

    @abstractmethod
    def get(self, query, table_or_collection):
        """
        Retrieves one or more objects in the specified table or collection.
        """
        pass

    @abstractmethod
    def put(self, item, table_or_collection):
        """Stores one or more objects in the specified table or collection."""
        pass

    @property
    @abstractmethod
    def conn_details(self):
        pass


# Predefined names of collections to classify statistical data.
COLLECTIONS = ["benign_with_crypto", "benign_without_crypto",
               "malware_with_crypto", "malware_with_crypto"]


# Implementation of a mongodb database client using pymongo.
class NoSQLDatabase(Database):
    """Abstraction of pymongo database."""

    def __init__(self, os, arch, address="localhost", port=27017):
        super(NoSQLDatabase, self).__init__()
        self.client = pymongo.MongoClient(address, port)
        self.db = self.client[os.lower() + "_" + arch.lower()]

    def get(self, query, collection):
        if collection not in COLLECTIONS:
            fmt = "Invalid collection: '{}'. Valid choices are {}"
            raise ValueError(fmt.format(collection, ", ".join(COLLECTIONS)))

        # If searching for 'filename', it won't exist. We must rename it first.
        if "filename" in query:
            query["_id"] = query.pop("filename")

        docs = list(self.db[collection].find(query))

        # We need to rename the '_id' field back to 'filename'.
        for i in range(len(docs)):
            docs[i]["filename"] = docs[i].pop("_id")

        return docs

    def put(self, docs, collection):
        if collection not in COLLECTIONS:
            fmt = "Invalid collection: '{}'. Valid choices are {}"
            raise ValueError(fmt.format(collection, ", ".join(COLLECTIONS)))

        # Insert many if docs is a list.
        if isinstance(docs, list):
            # pymongo requires an '_id' field, otherwise it inserts one.
            # Renaming the 'filename' field to act as an ID. Will throw a
            # KeyError exception if this field does not exist!
            for i in range(len(docs)):
                docs[i]["_id"] = docs[i].pop("filename")

            return self.db[collection].insert_many(docs)

        # Otherwise, insert one.
        docs["_id"] = docs.pop("filename")
        return self.db[collection].insert_one(docs)

    # Properties.
    @property
    def conn_details(self):
        return self.client.address
