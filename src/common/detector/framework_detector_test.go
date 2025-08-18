package detector

import (
	"testing"

	"github.com/asii-mov/codesucks-ai/common"
	"github.com/stretchr/testify/assert"
)

func TestDetectFrameworks_ReactApp(t *testing.T) {
	files := []common.RepositoryFile{
		{Path: "package.json", Type: "file", Content: `{
			"dependencies": {
				"react": "^18.0.0",
				"react-dom": "^18.0.0"
			},
			"devDependencies": {
				"webpack": "^5.0.0"
			}
		}`},
		{Path: "src/App.jsx", Type: "file"},
		{Path: "src/components/Header.jsx", Type: "file"},
		{Path: "webpack.config.js", Type: "file"},
	}

	detector := NewFrameworkDetector()
	result := detector.DetectFrameworks(files, "JavaScript")

	assert.Equal(t, "React", result.Primary)
	// Webpack should be detected as a build tool from package.json
	assert.Contains(t, result.BuildTools, "Webpack")
	assert.Equal(t, "package.json", result.Indicators["React"])
}

func TestDetectFrameworks_NextJSApp(t *testing.T) {
	files := []common.RepositoryFile{
		{Path: "package.json", Type: "file", Content: `{
			"dependencies": {
				"next": "^13.0.0",
				"react": "^18.0.0"
			}
		}`},
		{Path: "pages/index.js", Type: "file"},
		{Path: "pages/api/users.js", Type: "file"},
		{Path: "next.config.js", Type: "file"},
	}

	detector := NewFrameworkDetector()
	result := detector.DetectFrameworks(files, "JavaScript")

	assert.Equal(t, "Next.js", result.Primary)
	assert.Contains(t, result.Secondary, "React")
	assert.Equal(t, "package.json", result.Indicators["Next.js"])
}

func TestDetectFrameworks_DjangoApp(t *testing.T) {
	files := []common.RepositoryFile{
		{Path: "requirements.txt", Type: "file", Content: "Django==4.0.0\npsycopg2==2.9.0"},
		{Path: "manage.py", Type: "file"},
		{Path: "settings.py", Type: "file"},
		{Path: "models.py", Type: "file"},
		{Path: "views.py", Type: "file"},
	}

	detector := NewFrameworkDetector()
	result := detector.DetectFrameworks(files, "Python")

	assert.Equal(t, "Django", result.Primary)
	assert.Contains(t, result.Database, "PostgreSQL")
	assert.Equal(t, "requirements.txt", result.Indicators["Django"])
}

func TestDetectFrameworks_FlaskApp(t *testing.T) {
	files := []common.RepositoryFile{
		{Path: "requirements.txt", Type: "file", Content: "Flask==2.0.0\nFlask-SQLAlchemy==2.5.0"},
		{Path: "app.py", Type: "file"},
		{Path: "routes.py", Type: "file"},
		{Path: "models.py", Type: "file"},
	}

	detector := NewFrameworkDetector()
	result := detector.DetectFrameworks(files, "Python")

	assert.Equal(t, "Flask", result.Primary)
	assert.Contains(t, result.Secondary, "SQLAlchemy")
	assert.Equal(t, "requirements.txt", result.Indicators["Flask"])
	assert.Equal(t, "requirements.txt", result.Indicators["SQLAlchemy"])
}

func TestDetectFrameworks_SpringBootApp(t *testing.T) {
	files := []common.RepositoryFile{
		{Path: "pom.xml", Type: "file", Content: `<project>
			<dependencies>
				<dependency>
					<groupId>org.springframework.boot</groupId>
					<artifactId>spring-boot-starter-web</artifactId>
				</dependency>
			</dependencies>
		</project>`},
		{Path: "src/main/java/Application.java", Type: "file"},
		{Path: "src/main/java/controller/UserController.java", Type: "file"},
		{Path: "application.properties", Type: "file"},
	}

	detector := NewFrameworkDetector()
	result := detector.DetectFrameworks(files, "Java")

	assert.Equal(t, "Spring Boot", result.Primary)
	assert.Equal(t, "pom.xml", result.Indicators["Spring Boot"])
}

func TestDetectFrameworks_LaravelApp(t *testing.T) {
	files := []common.RepositoryFile{
		{Path: "composer.json", Type: "file", Content: `{
			"require": {
				"laravel/framework": "^9.0"
			}
		}`},
		{Path: "artisan", Type: "file"},
		{Path: "app/Http/Controllers/UserController.php", Type: "file"},
		{Path: "routes/web.php", Type: "file"},
		{Path: "config/app.php", Type: "file"},
	}

	detector := NewFrameworkDetector()
	result := detector.DetectFrameworks(files, "PHP")

	assert.Equal(t, "Laravel", result.Primary)
	assert.Equal(t, "composer.json", result.Indicators["Laravel"])
}

func TestDetectFrameworks_RailsApp(t *testing.T) {
	files := []common.RepositoryFile{
		{Path: "Gemfile", Type: "file", Content: `gem 'rails', '~> 7.0.0'`},
		{Path: "config/application.rb", Type: "file"},
		{Path: "app/controllers/application_controller.rb", Type: "file"},
		{Path: "app/models/user.rb", Type: "file"},
		{Path: "db/migrate/001_create_users.rb", Type: "file"},
	}

	detector := NewFrameworkDetector()
	result := detector.DetectFrameworks(files, "Ruby")

	assert.Equal(t, "Ruby on Rails", result.Primary)
	assert.Equal(t, "Gemfile", result.Indicators["Ruby on Rails"])
}

func TestDetectFrameworks_ExpressApp(t *testing.T) {
	files := []common.RepositoryFile{
		{Path: "package.json", Type: "file", Content: `{
			"dependencies": {
				"express": "^4.18.0",
				"cors": "^2.8.5"
			}
		}`},
		{Path: "server.js", Type: "file"},
		{Path: "routes/users.js", Type: "file"},
		{Path: "middleware/auth.js", Type: "file"},
	}

	detector := NewFrameworkDetector()
	result := detector.DetectFrameworks(files, "JavaScript")

	assert.Equal(t, "Express", result.Primary)
	assert.Equal(t, "package.json", result.Indicators["Express"])
}

func TestDetectFrameworks_GoGinApp(t *testing.T) {
	files := []common.RepositoryFile{
		{Path: "go.mod", Type: "file", Content: `module myapp
require github.com/gin-gonic/gin v1.9.0`},
		{Path: "main.go", Type: "file"},
		{Path: "handlers/user.go", Type: "file"},
	}

	detector := NewFrameworkDetector()
	result := detector.DetectFrameworks(files, "Go")

	assert.Equal(t, "Gin", result.Primary)
	assert.Equal(t, "go.mod", result.Indicators["Gin"])
}

func TestDetectFrameworks_MultipleFrameworks(t *testing.T) {
	files := []common.RepositoryFile{
		{Path: "package.json", Type: "file", Content: `{
			"dependencies": {
				"react": "^18.0.0",
				"express": "^4.18.0"
			}
		}`},
		{Path: "client/src/App.jsx", Type: "file"},
		{Path: "server/index.js", Type: "file"},
		{Path: "docker-compose.yml", Type: "file"},
	}

	detector := NewFrameworkDetector()
	result := detector.DetectFrameworks(files, "JavaScript")

	// Should detect one as primary and others as secondary
	assert.NotEmpty(t, result.Primary)
	assert.NotEmpty(t, result.Secondary)

	// Should detect both React and Express
	allFrameworks := append(result.Secondary, result.Primary)
	assert.Contains(t, allFrameworks, "React")
	assert.Contains(t, allFrameworks, "Express")
}

func TestDetectFrameworks_NoFramework(t *testing.T) {
	files := []common.RepositoryFile{
		{Path: "README.md", Type: "file"},
		{Path: "LICENSE", Type: "file"},
		{Path: "script.js", Type: "file"},
	}

	detector := NewFrameworkDetector()
	result := detector.DetectFrameworks(files, "JavaScript")

	assert.Equal(t, "None", result.Primary)
	assert.Empty(t, result.Secondary)
	assert.Empty(t, result.Indicators)
}

func TestGetFrameworkRulesets_React(t *testing.T) {
	frameworks := common.FrameworkDetection{
		Primary:   "React",
		Secondary: []string{"Express"},
	}

	detector := NewFrameworkDetector()
	rulesets := detector.GetFrameworkRulesets(frameworks)

	assert.Contains(t, rulesets, "p/react")
	assert.Contains(t, rulesets, "p/javascript")
}

func TestGetFrameworkRulesets_Django(t *testing.T) {
	frameworks := common.FrameworkDetection{
		Primary:   "Django",
		Secondary: []string{},
	}

	detector := NewFrameworkDetector()
	rulesets := detector.GetFrameworkRulesets(frameworks)

	assert.Contains(t, rulesets, "p/django")
}

func TestGetFrameworkRulesets_None(t *testing.T) {
	frameworks := common.FrameworkDetection{
		Primary:   "None",
		Secondary: []string{},
	}

	detector := NewFrameworkDetector()
	rulesets := detector.GetFrameworkRulesets(frameworks)

	assert.Empty(t, rulesets)
}

func TestAnalyzePackageJSON(t *testing.T) {
	content := `{
		"dependencies": {
			"react": "^18.0.0",
			"next": "^13.0.0",
			"express": "^4.18.0"
		},
		"devDependencies": {
			"webpack": "^5.0.0",
			"typescript": "^4.9.0"
		}
	}`

	detector := NewFrameworkDetector()
	frameworks, buildTools := detector.analyzePackageJSON(content)

	assert.Contains(t, frameworks, "React")
	assert.Contains(t, frameworks, "Next.js")
	assert.Contains(t, frameworks, "Express")
	assert.Contains(t, buildTools, "Webpack")
	assert.Contains(t, buildTools, "TypeScript")
}

func TestAnalyzeRequirementsTxt(t *testing.T) {
	content := `Django==4.0.0
Flask==2.0.0
FastAPI==0.68.0
psycopg2==2.9.0
redis==3.5.3`

	detector := NewFrameworkDetector()
	frameworks, databases := detector.analyzeRequirementsTxt(content)

	assert.Contains(t, frameworks, "Django")
	assert.Contains(t, frameworks, "Flask")
	assert.Contains(t, frameworks, "FastAPI")
	assert.Contains(t, databases, "PostgreSQL")
	assert.Contains(t, databases, "Redis")
}

func TestAnalyzePomXML(t *testing.T) {
	content := `<project>
		<dependencies>
			<dependency>
				<groupId>org.springframework.boot</groupId>
				<artifactId>spring-boot-starter-web</artifactId>
			</dependency>
			<dependency>
				<groupId>org.springframework.security</groupId>
				<artifactId>spring-security-core</artifactId>
			</dependency>
		</dependencies>
	</project>`

	detector := NewFrameworkDetector()
	frameworks, security := detector.analyzePomXML(content)

	assert.Contains(t, frameworks, "Spring Boot")
	assert.Contains(t, security, "Spring Security")
}
