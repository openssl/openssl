pipeline {
  agent any
  stages {
    stage('stage1') {
      parallel {
        stage('stage1') {
          steps {
            bat(script: 'env', encoding: 'utf-8', returnStdout: true)
          }
        }
        stage('stage2') {
          steps {
            bat 'env'
          }
        }
        stage('stage22') {
          steps {
            echo 'stage22'
          }
        }
      }
    }
    stage('stage3') {
      parallel {
        stage('stage3') {
          steps {
            echo 'stage3'
          }
        }
        stage('stage4') {
          steps {
            sleep 1
          }
        }
      }
    }
  }
}