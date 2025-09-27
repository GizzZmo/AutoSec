# Contributing to AutoSec

Thank you for your interest in contributing to AutoSec! This guide will help you get started with contributing to our advanced cybersecurity operations platform.

## 🤝 Ways to Contribute

### Code Contributions
- **Bug fixes**: Help us fix issues and improve stability
- **New features**: Implement new cybersecurity capabilities
- **Integrations**: Add support for new security tools and platforms
- **Performance improvements**: Optimize algorithms and system performance
- **Documentation**: Improve and expand our documentation

### Non-Code Contributions
- **Bug reports**: Help us identify and track issues
- **Feature requests**: Suggest new capabilities and improvements
- **Documentation**: Write tutorials, guides, and examples
- **Community support**: Help other users in discussions and forums
- **Testing**: Test new features and provide feedback

## 🚀 Getting Started

### Prerequisites
Before contributing, ensure you have:
- **Git**: Version control system
- **Docker & Docker Compose**: For running the development environment
- **Node.js 18+**: For backend development (Node.js 20+ recommended)
- **npm or yarn**: Package manager
- **Code Editor**: VS Code, IntelliJ, or your preferred editor

### Development Setup

1. **Fork and Clone**
   ```bash
   # Fork the repository on GitHub
   git clone https://github.com/YOUR_USERNAME/AutoSec.git
   cd AutoSec
   
   # Add upstream remote
   git remote add upstream https://github.com/GizzZmo/AutoSec.git
   ```

2. **Environment Setup**
   ```bash
   # Copy environment configuration
   cp backend/.env.example backend/.env
   cp frontend/.env.example frontend/.env
   
   # Generate secure secrets for development
   openssl rand -base64 64  # Use for JWT_SECRET in backend/.env
   ```

3. **Start Development Services**
   ```bash
   # Start only databases and message broker for development
   docker compose up postgres mongodb redis rabbitmq -d
   
   # Wait for services to be healthy
   docker compose ps
   ```

4. **Install Dependencies**
   ```bash
   # Backend dependencies
   cd backend
   npm install
   
   # Frontend dependencies
   cd ../frontend
   npm install
   ```

5. **Initialize Database**
   ```bash
   cd backend
   npm run db:migrate
   npm run db:seed
   ```

6. **Start Development Servers**
   ```bash
   # Start backend (in one terminal)
   cd backend
   npm run dev
   
   # Start frontend (in another terminal)
   cd frontend
   npm start
   ```

### Development Workflow

1. **Create a Feature Branch**
   ```bash
   # Keep your main branch updated
   git checkout main
   git pull upstream main
   
   # Create a new feature branch
   git checkout -b feature/your-feature-name
   ```

2. **Make Your Changes**
   - Follow our coding standards (see below)
   - Write tests for new functionality
   - Update documentation as needed
   - Ensure your changes work with existing features

3. **Test Your Changes**
   ```bash
   # Backend tests
   cd backend
   npm test
   npm run test:coverage
   
   # Frontend tests
   cd frontend
   npm test
   
   # Linting
   npm run lint
   npm run lint:fix
   ```

4. **Commit Your Changes**
   ```bash
   # Stage your changes
   git add .
   
   # Commit with a descriptive message
   git commit -m "feat: add new threat detection algorithm"
   ```

5. **Push and Create Pull Request**
   ```bash
   # Push your branch
   git push origin feature/your-feature-name
   
   # Create a pull request on GitHub
   ```

## 📋 Development Guidelines

### Coding Standards

#### Backend (Node.js)
- **ES6+ JavaScript**: Use modern JavaScript features
- **ESLint**: Follow the project's ESLint configuration
- **Prettier**: Use Prettier for code formatting
- **JSDoc**: Document functions and classes
- **Error Handling**: Always handle errors gracefully
- **Security**: Follow secure coding practices

```javascript
/**
 * Analyzes user behavior patterns for anomaly detection
 * @param {string} userId - The user ID to analyze
 * @param {Object} timeRange - Time range for analysis
 * @param {Date} timeRange.start - Start time
 * @param {Date} timeRange.end - End time
 * @returns {Promise<Object>} Analysis results with risk score
 */
async function analyzeUserBehavior(userId, timeRange) {
  try {
    // Implementation here
    return { riskScore: 0.75, anomalies: [] };
  } catch (error) {
    logger.error('Error analyzing user behavior:', error);
    throw new Error('Analysis failed');
  }
}
```

#### Frontend (React)
- **Functional Components**: Use React hooks instead of class components
- **JSX**: Follow React best practices
- **ESLint**: Follow React-specific linting rules
- **Component Structure**: Keep components small and focused
- **State Management**: Use React hooks for state management

```javascript
import React, { useState, useEffect } from 'react';

/**
 * Dashboard component showing security metrics
 */
const Dashboard = () => {
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchMetrics();
  }, []);

  const fetchMetrics = async () => {
    try {
      const response = await api.get('/analytics/dashboard');
      setMetrics(response.data);
    } catch (error) {
      console.error('Failed to fetch metrics:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <div>Loading...</div>;

  return (
    <div className="dashboard">
      {/* Component content */}
    </div>
  );
};

export default Dashboard;
```

### Testing Standards

#### Unit Tests
- **Coverage**: Maintain 90%+ test coverage
- **Jest**: Use Jest for testing framework
- **Mocking**: Mock external dependencies
- **Test Structure**: Use describe/it blocks clearly

```javascript
describe('User Behavior Analysis', () => {
  describe('analyzeUserBehavior', () => {
    it('should return risk score for valid user', async () => {
      // Arrange
      const userId = 'user123';
      const timeRange = { start: new Date(), end: new Date() };
      
      // Act
      const result = await analyzeUserBehavior(userId, timeRange);
      
      // Assert
      expect(result).toHaveProperty('riskScore');
      expect(result.riskScore).toBeGreaterThanOrEqual(0);
      expect(result.riskScore).toBeLessThanOrEqual(1);
    });

    it('should throw error for invalid user', async () => {
      // Arrange
      const invalidUserId = 'invalid';
      const timeRange = { start: new Date(), end: new Date() };
      
      // Act & Assert
      await expect(analyzeUserBehavior(invalidUserId, timeRange))
        .rejects.toThrow('Analysis failed');
    });
  });
});
```

#### Integration Tests
- **API Testing**: Test complete API workflows
- **Database Testing**: Test database interactions
- **Service Integration**: Test service-to-service communication

### Documentation Standards

#### Code Documentation
- **JSDoc**: Document all public functions and classes
- **README**: Keep component READMEs updated
- **Inline Comments**: Explain complex logic
- **API Documentation**: Update Swagger/OpenAPI specs

#### User Documentation
- **Clear Instructions**: Write step-by-step guides
- **Examples**: Include practical examples
- **Screenshots**: Add visual aids where helpful
- **Keep Updated**: Ensure documentation matches current features

## 🐛 Bug Reports

When reporting bugs, please include:

### Bug Report Template
```markdown
**Bug Description**
A clear description of what the bug is.

**Steps to Reproduce**
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

**Expected Behavior**
What you expected to happen.

**Actual Behavior**
What actually happened.

**Environment**
- OS: [e.g. Ubuntu 20.04]
- Docker version: [e.g. 20.10.17]
- Browser (if applicable): [e.g. Chrome 96]
- AutoSec version: [e.g. 1.0.0]

**Logs**
Include relevant log output or error messages.

**Screenshots**
Add screenshots if applicable.
```

## ✨ Feature Requests

### Feature Request Template
```markdown
**Feature Description**
A clear description of the feature you'd like to see.

**Use Case**
Explain how this feature would be used and why it's valuable.

**Proposed Solution**
Describe how you think this could be implemented.

**Alternatives Considered**
Any alternative solutions or features you've considered.

**Additional Context**
Any other context, screenshots, or examples.
```

## 🔒 Security Issues

**Do not report security vulnerabilities in public issues.**

For security issues:
1. **Email**: Send details to the maintainers privately
2. **Encrypted Communication**: Use GPG if available
3. **Responsible Disclosure**: Allow time for fixes before disclosure
4. **Recognition**: We'll acknowledge your contribution

## 📝 Pull Request Guidelines

### PR Requirements
- **Branch**: Create from latest `main` branch
- **Tests**: Include tests for new functionality
- **Documentation**: Update relevant documentation
- **Changelog**: Add entry to CHANGELOG.md
- **Commits**: Use conventional commit messages

### PR Template
```markdown
## Description
Brief description of changes.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex code
- [ ] Documentation updated
- [ ] No new warnings introduced
```

### Commit Message Format
We use [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): description

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Test changes
- `chore`: Build/tool changes

**Examples:**
```
feat(auth): add multi-factor authentication support
fix(api): resolve rate limiting issue
docs(readme): update installation instructions
test(behavior): add unit tests for anomaly detection
```

## 🧪 Testing Your Contributions

### Local Testing
```bash
# Run all tests
npm run test:all

# Run specific test suites
npm run test:unit
npm run test:integration
npm run test:e2e

# Check code coverage
npm run test:coverage

# Security testing
npm audit
npm run security:check
```

### Manual Testing
1. **Feature Testing**: Test your new feature thoroughly
2. **Regression Testing**: Ensure existing features still work
3. **Cross-Browser Testing**: Test UI changes in different browsers
4. **Performance Testing**: Check for performance impacts

### CI/CD Pipeline
Our CI/CD pipeline will automatically:
- Run all tests
- Check code quality
- Build Docker images
- Deploy to staging environment

## 🏆 Recognition

We value all contributions and provide recognition through:
- **Contributors List**: Listed in README and documentation
- **Release Notes**: Mentioned in release announcements
- **Community Highlights**: Featured in community updates
- **Swag**: Stickers and other items for significant contributions

## 📚 Additional Resources

### Learning Resources
- **Architecture Guide**: [docs/developer-guide/architecture.md](../developer-guide/architecture.md)
- **API Documentation**: [docs/api/endpoints.md](../api/endpoints.md)
- **Security Guide**: [docs/security/architecture.md](../security/architecture.md)

### Communication Channels
- **GitHub Discussions**: General questions and ideas
- **GitHub Issues**: Bug reports and feature requests
- **Pull Requests**: Code reviews and discussions

### Code Style Tools
```bash
# Install development tools
npm install -g eslint prettier

# Setup IDE integration
# VS Code: Install ESLint and Prettier extensions
# IntelliJ: Enable ESLint and Prettier plugins
```

## ❓ Getting Help

If you need help contributing:
1. **Read Documentation**: Check our comprehensive docs
2. **GitHub Discussions**: Ask questions in discussions
3. **Join Community**: Engage with other contributors
4. **Contact Maintainers**: Reach out to project maintainers

Thank you for contributing to AutoSec! Together, we're building the future of cybersecurity operations.

---

*This guide is continuously updated. For the latest version, check the repository.*