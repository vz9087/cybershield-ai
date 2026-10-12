module.exports = {
  hooks: {
    readPackage(pkg) {
      // Force drizzle-kit to see mysql2 as a dependency
      if (pkg.name === 'drizzle-kit') {
        pkg.dependencies = pkg.dependencies || {};
        pkg.dependencies['mysql2'] = '*';
      }
      return pkg;
    }
  }
};