var gulp = require('gulp'),
    jshint = require('gulp-jshint'),
    sourcemaps = require('gulp-sourcemaps'),
    concat = require('gulp-concat'),
    uglify = require('gulp-uglify')

var js_sources = 'src/**/*.js';
var js_build = 'dist/';
var js_build_file = 'pwnfox.js';

gulp.task('jshint', function() {
  return gulp.src(js_sources)
    .pipe(jshint())
    .pipe(jshint.reporter('jshint-stylish'))
});

gulp.task('watch', function() {
  gulp.watch(js_sources, gulp.series(['jshint']));
});

gulp.task('build', function() {
  return gulp.src(js_sources)
    .pipe(sourcemaps.init())
    .pipe(concat(js_build_file))
    .pipe(uglify())
    .pipe(sourcemaps.write())
    .pipe(gulp.dest(js_build));
});

gulp.task('default', gulp.series(['watch']));
