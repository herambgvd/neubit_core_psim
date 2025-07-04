# Neubit PSIM Core Platform Service

[![Build Status](https://github.com/neubit/psim-core-platform/workflows/CI/badge.svg)](https://github.com/neubit/psim-core-platform/actions)
[![Python Version](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![Django Version](https://img.shields.io/badge/django-4.2+-green.svg)](https://djangoproject.com)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

The Core Platform Service is the central authentication, authorization, and location management hub for the Neubit PSIM (Physical Security Information Management) ecosystem. Built with Django and designed as a microservice, it provides centralized user management, role-based access control (RBAC), and location hierarchy management for all PSIM services.

## 🏗️ Architecture

The Core Platform follows a microservices architecture and serves as the authentication and authorization provider for the entire PSIM ecosystem:

```
┌─────────────────────────────────────────────────────────────────┐
│                        Kong API Gateway                         │
│              (Service Discovery & API Management)               │
└─────────────────────┬───────────────────────────────────────────┘
                      │
    ┌─────────────────┼─────────────────┐
    │                 │                 │
    ▼                 ▼                 ▼
┌─────────┐    ┌─────────────┐    ┌──────────────┐
│  Core   │    │   FastAPI   │    │   FastAPI    │
│Platform │    │Microservices│    │ Microservices│
│(Django) │    │             │    │              │
├─────────┤    ├─────────────┤    ├──────────────┤
│• Users  │    │• Video Mgmt │    │• Access Ctrl │
│• Auth   │    │• Cameras    │    │• Door Ctrl   │
│• RBAC   │    │• Streaming  │    │• Card Readers│
│• Locations│  │• Recording  │    │• Biometrics  │
│• Audit  │    │• Analytics  │    │• Policies    │
└─────────┘    └─────────────┘    └──────────────┘
```

## ✨ Features

### Phase 1 (Current) - Foundation & Infrastructure
- ✅ **Microservice Architecture**: Production-ready Django microservice
- ✅ **Health Monitoring**: Comprehensive health check system
- ✅ **Database Integration**: PostgreSQL with connection pooling
- ✅ **Caching System**: Redis-based distributed caching
- ✅ **Message Queue**: Celery with Redis broker
- ✅ **Kong Integration**: API Gateway registration and management
- ✅ **Security Framework**: Enterprise-grade security middleware
- ✅ **Monitoring Stack**: Prometheus, Grafana, and Jaeger integration
- ✅ **Service Discovery**: Automatic service registration
- ✅ **Containerization**: Docker development and production environments

### Phase 2 (Upcoming) - Authentication & User Management
- 🔄 **JWT Authentication**: Service-to-service and user authentication
- 🔄 **User Management**: Complete user lifecycle management
- 🔄 **RBAC System**: Role-based access control with fine-grained permissions
- 🔄 **Multi-Factor Auth**: 2FA and security enhancement preparation

### Phase 3 (Planned) - Location Management
- 📋 **Hierarchical Locations**: Site → Building → Floor → Zone → Room structure
- 📋 **Device Integration**: Device-to-location mapping and tracking
- 📋 **Floor Plan Management**: Visual floor plans with device positioning
- 📋 **Geographic Data**: GPS coordinates and address management

## 🚀 Quick Start

### Prerequisites

- **Docker & Docker Compose**: Latest version
- **Python 3.11+**: For local development
- **Git**: For version control
- **Make**: For development commands

### Development Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/neubit/psim-core-platform.git
   cd psim-core-platform
   ```

2. **Quick setup with Make**:
   ```bash
   make setup
   ```

   This command will:
   - Build all Docker containers
   - Start the development environment
   - Run database migrations
   - Collect static files
   - Create a development superuser
   - Register with Kong Gateway

3. **Verify installation**:
   ```bash
   make health
   ```

### Manual Setup

If you prefer manual setup or don't have Make:

```bash
# Build and start services
docker-compose -f docker-compose.dev.yml up -d

# Run migrations
docker-compose -f docker-compose.dev.yml exec core-platform python manage.py migrate

# Create superuser
docker-compose -f docker-compose.dev.yml exec core-platform python manage.py create_dev_superuser

# Register with Kong
docker-compose -f docker-compose.dev.yml exec core-platform python manage.py register_with_kong
```

## 🔗 Service Endpoints

Once running, the following services are available:

| Service | URL | Description |
|---------|-----|-------------|
| Core Platform API | http://localhost:8080 | Main API endpoints |
| API Documentation | http://localhost:8080/api/docs/ | Swagger UI documentation |
| Health Checks | http://localhost:8080/health/ | Service health monitoring |
| Django Admin | http://localhost:8080/admin/ | Admin interface (admin/admin@123) |
| Kong Gateway | http://localhost:8000 | API Gateway proxy |
| Kong Admin | http://localhost:8001 | Kong administration |
| Konga UI | http://localhost:1337 | Kong management interface |
| Flower | http://localhost:5555 | Celery task monitoring |
| Grafana | http://localhost:3000 | Monitoring dashboards (admin/admin) |
| Prometheus | http://localhost:9090 | Metrics collection |
| Jaeger | http://localhost:16686 | Distributed tracing |

## 🛠️ Development

### Common Commands

```bash
# Development lifecycle
make up                    # Start all services
make down                  # Stop all services
make restart               # Restart all services
make logs                  # View all logs
make logs-core             # View core platform logs

# Database operations
make migrate               # Run migrations
make makemigrations        # Create new migrations
make superuser             # Create development superuser

# Code quality
make lint                  # Run linting
make format                # Format code
make test                  # Run tests
make security-check        # Run security checks

# Kong integration
make kong-register         # Register with Kong
make kong-check            # Check registration status
make kong-unregister       # Unregister from Kong

# Utilities
make shell                 # Django shell
make bash                  # Container bash shell
make monitor               # Open monitoring dashboards
```

### Project Structure

```
neubit-psim-core/
├── apps/                          # Django applications
│   ├── authentication/           # Authentication services
│   ├── users/                     # User management
│   ├── locations/                 # Location management
│   ├── audit/                     # Audit logging
│   └── shared/                    # Shared utilities
│       ├── health/                # Health check system
│       ├── middleware/            # Custom middleware
│       ├── services/              # Shared services
│       └── management/commands/   # Management commands
├── core/                          # Django project settings
│   ├── settings/                  # Environment-specific settings
│   │   ├── base.py                # Base settings
│   │   ├── development.py         # Development settings
│   │   ├── production.py          # Production settings
│   │   └── testing.py             # Testing settings
│   ├── celery.py                  # Celery configuration
│   ├── urls.py                    # Main URL configuration
│   ├── wsgi.py                    # WSGI application
│   └── asgi.py                    # ASGI application
├── infrastructure/               # Infrastructure configuration
│   ├── docker/                    # Docker configurations
│   ├── kubernetes/                # Kubernetes manifests
│   ├── kong/                      # Kong configurations
│   └── monitoring/                # Monitoring configurations
├── requirements/                  # Python dependencies
│   ├── base.txt                   # Base requirements
│   ├── dev.txt                    # Development requirements
│   └── prod.txt                   # Production requirements
├── tests/                         # Test suites
├── docs/                          # Documentation
├── scripts/                       # Utility scripts
├── docker-compose.dev.yml         # Development environment
├── docker-compose.prod.yml        # Production environment
├── Makefile                       # Development commands
└── README.md                      # This file
```

## 🔒 Security

The Core Platform implements enterprise-grade security features:

- **Authentication**: JWT-based authentication with refresh tokens
- **Authorization**: Fine-grained RBAC system
- **Encryption**: Data encryption at rest and in transit
- **Security Headers**: Comprehensive security headers middleware
- **Rate Limiting**: API rate limiting and throttling
- **Audit Logging**: Complete audit trail for all operations
- **Input Validation**: Comprehensive input validation and sanitization
- **CORS Protection**: Configurable CORS policies

## 📊 Monitoring & Observability

### Health Checks

The platform provides multiple health check endpoints:

- **Comprehensive**: `/health/` - Full system health check
- **Readiness**: `/health/ready/` - Kubernetes readiness probe
- **Liveness**: `/health/live/` - Kubernetes liveness probe
- **Component-specific**: `/health/component/<name>/` - Individual component health
- **Metrics**: `/health/metrics/` - Prometheus-compatible metrics

### Monitoring Stack

- **Prometheus**: Metrics collection and alerting
- **Grafana**: Visualization and dashboards
- **Jaeger**: Distributed tracing
- **Flower**: Celery task monitoring
- **Structured Logging**: JSON-formatted logs with correlation IDs

## 🚀 Deployment

### Development Deployment

The development environment is fully containerized and includes all dependencies:

```bash
make setup    # Complete development setup
make up       # Start development environment
```

### Production Deployment

Production deployment uses optimized containers with security hardening:

```bash
# Build production images
make prod-build

# Deploy to production
make prod-up

# Monitor production
make prod-logs
```

### Environment Variables

Key environment variables for production:

```bash
# Core Configuration
DJANGO_SETTINGS_MODULE=core.settings.production
DEBUG=False
SECRET_KEY=your-super-secret-key
ALLOWED_HOSTS=yourdomain.com,api.yourdomain.com

# Database
DATABASE_URL=postgresql://user:password@host:port/database

# Cache & Queue
REDIS_URL=redis://user:password@host:port/db
CELERY_BROKER_URL=redis://user:password@host:port/db

# Kong Integration
KONG_ADMIN_URL=https://kong-admin.yourdomain.com
SERVICE_URL=https://core-platform.yourdomain.com

# Security
CORS_ALLOWED_ORIGINS=https://app.yourdomain.com
CSRF_TRUSTED_ORIGINS=https://yourdomain.com

# Monitoring
SENTRY_DSN=https://your-sentry-dsn@sentry.io/project
```

## 🧪 Testing

### Running Tests

```bash
# Run all tests
make test

# Run with coverage
make test-coverage

# Run specific app tests
docker-compose -f docker-compose.dev.yml exec core-platform python manage.py test apps.shared

# Run load tests
make load-test
```

### Test Categories

- **Unit Tests**: Individual component testing
- **Integration Tests**: Service integration testing
- **API Tests**: REST API endpoint testing
- **Health Check Tests**: System health verification
- **Performance Tests**: Load and stress testing

## 📚 API Documentation

### Interactive Documentation

The API documentation is automatically generated and available at:
- **Swagger UI**: http://localhost:8080/api/docs/
- **ReDoc**: http://localhost:8080/api/redoc/
- **OpenAPI Schema**: http://localhost:8080/api/schema/

### API Structure

```
/api/v1/
├── auth/          # Authentication endpoints
├── users/         # User management endpoints
├── locations/     # Location management endpoints
└── audit/         # Audit log endpoints
```

## 🔧 Configuration

### Django Settings

The platform uses environment-specific settings:

- **`base.py`**: Common settings for all environments
- **`development.py`**: Development-specific settings
- **`production.py`**: Production-optimized settings
- **`testing.py`**: Testing environment settings

### Kong Configuration

Kong Gateway integration provides:

- **Service Registration**: Automatic service registration
- **Route Management**: API route configuration
- **Plugin Configuration**: Security and monitoring plugins
- **Load Balancing**: Upstream load balancing

## 📈 Performance

### Optimization Features

- **Database Connection Pooling**: Optimized database connections
- **Redis Caching**: Multi-level caching strategy
- **Static File Optimization**: Compressed and versioned static files
- **Async Task Processing**: Background task processing with Celery
- **Response Compression**: Gzip compression for API responses

### Performance Metrics

- **Target Response Time**: <200ms (95th percentile)
- **Database Query Time**: <10ms average
- **Cache Hit Rate**: >90%
- **Uptime Target**: >99.9%

## 🤝 Contributing

We welcome contributions to the Core Platform! Please follow these guidelines:

1. **Fork the repository** and create a feature branch
2. **Follow code style**: Use Black for formatting and follow PEP 8
3. **Write tests**: Ensure new features have appropriate test coverage
4. **Update documentation**: Update relevant documentation
5. **Submit a pull request**: Provide a clear description of changes

### Development Workflow

```bash
# Setup development environment
git clone https://github.com/neubit/psim-core-platform.git
cd psim-core-platform
make setup

# Create feature branch
git checkout -b feature/your-feature-name

# Make changes and test
make test
make lint
make format

# Commit and push
git commit -m "Add your feature"
git push origin feature/your-feature-name
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### Getting Help

- **Documentation**: Check the `/docs` directory for detailed documentation
- **Issues**: Report bugs and request features on GitHub Issues
- **Health Checks**: Use `/health/` endpoints to diagnose issues
- **Logs**: Check service logs with `make logs`

### Troubleshooting

Common issues and solutions:

#### Database Connection Issues
```bash
# Check database status
make logs postgres

# Verify database connectivity
docker-compose -f docker-compose.dev.yml exec core-platform python manage.py wait_for_db

# Reset database
docker-compose -f docker-compose.dev.yml down -v
make setup
```

#### Kong Registration Issues
```bash
# Check Kong status
make kong-check

# Re-register with Kong
make kong-register --force

# Check Kong logs
docker-compose -f docker-compose.dev.yml logs kong
```

#### Service Health Issues
```bash
# Check overall health
make health

# Check specific component health
curl http://localhost:8080/health/component/database/
curl http://localhost:8080/health/component/cache/
```

#### Performance Issues
```bash
# Check system metrics
curl http://localhost:8080/health/metrics/

# Monitor Celery tasks
# Visit http://localhost:5555

# Check Grafana dashboards
# Visit http://localhost:3000
```

## 🗺️ Roadmap

### Phase 2: Authentication & User Management (Q1 2025)
- Complete JWT authentication system
- User registration and profile management
- Multi-factor authentication (2FA)
- Password policies and security
- User session management
- Service-to-service authentication

### Phase 3: Location Management (Q2 2025)
- Hierarchical location structure
- Device-to-location mapping
- Floor plan management
- Geographic coordinates
- Zone-based access control
- Location-based permissions

### Phase 4: Advanced Features (Q3 2025)
- Advanced audit logging
- Data import/export
- Advanced notifications
- Configuration management
- Performance optimizations
- Additional security features

### Phase 5: Kong Integration & Orchestration (Q4 2025)
- Complete Kong Gateway integration
- Service mesh implementation
- Advanced routing and load balancing
- Enhanced monitoring and alerting
- Disaster recovery procedures

### Phase 6: Production Deployment (Q1 2026)
- Production infrastructure
- Migration from legacy systems
- Performance tuning
- Security hardening
- Compliance implementation
- 24/7 operational support

## 📊 Metrics & KPIs

### Technical Metrics
- **API Response Time**: Target <200ms (95th percentile)
- **System Uptime**: Target >99.9%
- **Database Performance**: Target <10ms query time
- **Cache Hit Rate**: Target >90%
- **Error Rate**: Target <0.1%

### Business Metrics
- **Service Integration**: All FastAPI services connected
- **User Experience**: Seamless authentication across services
- **Development Velocity**: 30% faster feature development
- **Operational Efficiency**: 50% reduction in auth issues
- **Security Posture**: Zero security incidents

## 🏢 Enterprise Features

### Security & Compliance
- **SOC 2 Compliance**: Security and availability controls
- **GDPR Compliance**: Data protection and privacy
- **Audit Trails**: Comprehensive audit logging
- **Encryption**: End-to-end data encryption
- **Access Controls**: Fine-grained permission system

### Scalability & Performance
- **Horizontal Scaling**: Auto-scaling capabilities
- **Load Balancing**: Intelligent load distribution
- **Caching Strategy**: Multi-layer caching system
- **Database Optimization**: Query optimization and indexing
- **CDN Integration**: Global content delivery

### Monitoring & Observability
- **Real-time Monitoring**: Live system monitoring
- **Alerting System**: Proactive issue detection
- **Performance Analytics**: Detailed performance insights
- **Custom Dashboards**: Business-specific monitoring
- **Log Aggregation**: Centralized log management

## 🌟 Key Benefits

### For Developers
- **Rapid Development**: Pre-built authentication and authorization
- **Standardized APIs**: Consistent API patterns across services
- **Comprehensive Documentation**: Auto-generated API documentation
- **Development Tools**: Rich development and debugging tools
- **Testing Framework**: Complete testing infrastructure

### For Operations
- **Health Monitoring**: Comprehensive health check system
- **Automated Deployment**: CI/CD pipeline integration
- **Scalability**: Easy horizontal and vertical scaling
- **Monitoring Integration**: Built-in monitoring and alerting
- **Disaster Recovery**: Backup and recovery procedures

### For Business
- **Cost Efficiency**: Reduced development and operational costs
- **Security**: Enterprise-grade security implementation
- **Compliance**: Built-in compliance features
- **Performance**: High-performance, low-latency operations
- **Reliability**: 99.9%+ uptime with automatic failover

## 📞 Contact

### Team
- **Architecture Team**: architecture@neubit.in
- **Development Team**: development@neubit.in
- **Operations Team**: operations@neubit.in
- **Security Team**: security@neubit.in

### Resources
- **Website**: https://neubit.in
- **Documentation**: https://docs.neubit.in/psim-core
- **Support Portal**: https://support.neubit.in
- **Status Page**: https://status.neubit.in

---

**Built with ❤️ by the Neubit Engineering Team**

*The Core Platform Service is part of the Neubit PSIM ecosystem, providing enterprise-grade physical security information management solutions.*