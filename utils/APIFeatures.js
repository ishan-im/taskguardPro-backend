class APIFeatures {
  constructor(query, queryString) {
    this.query = query;
    this.queryString = queryString;
  }

  filter() {
    let queryObject = { ...this.queryString };

    const excludeFields = ["sort", "page", "limit", "fields"];
    excludeFields.forEach((curr) => delete queryObject[curr]);

    const queryString = JSON.stringify(queryObject);

    queryObject = JSON.parse(
      queryString.replace(/\b(gt|gte|lt|lte)\b/g, (match) => `$${match}`) //\b\b for this to run when matches exactly, and g for replacing all
    );

    this.query = this.query.find(queryObject);

    return this;
  }

  sort() {
    if (this.queryString.sort) {
      const sortBy = this.queryString.sort.split(",").join(" ");
      this.query = this.query.sort(sortBy);
    } else {
      this.query = this.query.sort("-createdAt");
    }

    return this;
  }

  limitFields() {
    if (this.queryString.fields) {
      const fields = this.queryString.fields.split(",").join(" ");
      this.query = this.query.select(fields);
    } else {
      this.query = this.query.select("-__v");
    }

    return this;
  }

  paginate() {
    const page = this.queryString.page * 1 || 1;
    const limit = this.queryString.limit || 5;
    const skip = (page - 1) * limit;

    this.query = this.query.skip(skip).limit(limit);

    return this;
  }
}

module.exports = APIFeatures;
