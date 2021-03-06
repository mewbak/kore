pipeline {
  agent {
    dockerfile {
      additionalBuildArgs '--build-arg USER_ID=$(id -u) --build-arg GROUP_ID=$(id -g)'
    }
  }
  options {
    ansiColor('xterm')
  }
  stages {
    stage('Init title') {
      when { changeRequest() }
      steps {
        script {
          currentBuild.displayName = "PR ${env.CHANGE_ID}: ${env.CHANGE_TITLE}"
        }
      }
    }
    stage('Check') {
      steps {
        sh '''
          ./scripts/check.sh
        '''
      }
    }
    stage('Dependencies') {
      steps {
        sh '''
          ./scripts/clean.sh
          ./scripts/deps.sh
        '''
      }
    }
    stage('Build') {
      failFast true
      parallel {
        stage('Documentation') {
          steps {
            sh '''
              ./scripts/docs.sh
            '''
          }
        }
        stage('Executables') {
          steps {
            sh '''
              ./scripts/kore-exec.sh
            '''
          }
        }
      }
    }
    stage('Unit Tests') {
      steps {
        sh '''
          ./scripts/unit-test.sh
        '''
      }
      post {
        always {
          junit 'kore/test-results.xml'
        }
      }
    }
    stage('Integration: K') {
      options {
        timeout(time: 32, unit: 'MINUTES')
      }
      steps {
        sh '''
          ./scripts/integration-k.sh
        '''
      }
    }
    stage('Integration: KEVM') {
      options {
        timeout(time: 48, unit: 'MINUTES')
      }
      steps {
        sh '''
          ./scripts/integration-kevm.sh
        '''
        archiveArtifacts 'kevm-add0-stats.json'
        archiveArtifacts 'kevm-pop1-stats.json'
        archiveArtifacts 'kevm-sum-to-10-stats.json'
        archiveArtifacts 'kevm-sum-to-n-spec-stats.json'
      }
    }
    stage('Integration: KWASM') {
      options {
        timeout(time: 8, unit: 'MINUTES')
      }
      steps {
        sh '''
          ./scripts/integration-kwasm.sh
        '''
        archiveArtifacts 'kwasm-simple-arithmetic-spec-stats.json'
        archiveArtifacts 'kwasm-loops-spec-stats.json'
        archiveArtifacts 'kwasm-memory-symbolic-type-spec-stats.json'
        archiveArtifacts 'kwasm-locals-spec-stats.json'
      }
    }
    stage('Update K Submodules') {
      when { branch 'master' }
      steps {
        build job: 'rv-devops/master', propagate: false, wait: false                                                            \
            , parameters: [ booleanParam(name: 'UPDATE_DEPS_SUBMODULE', value: true)                                            \
                          , string(name: 'PR_REVIEWER', value: 'ttuegel')                                                       \
                          , string(name: 'UPDATE_DEPS_REPOSITORY', value: 'kframework/k')                                       \
                          , string(name: 'UPDATE_DEPS_SUBMODULE_DIR', value: 'haskell-backend/src/main/native/haskell-backend') \
                          ]
      }
    }
  }
  post {
    unsuccessful {
      script {
        if (env.BRANCH_NAME == 'master') {
          slackSend color: '#cb2431'                             \
                    , channel: '#haskell-backend'                \
                    , message: "Build failure: ${env.BUILD_URL}"
        }
      }
    }
  }
}
