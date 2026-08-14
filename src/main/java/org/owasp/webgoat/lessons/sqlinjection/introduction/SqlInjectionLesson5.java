/*
 * This file is part of WebGoat, an Open Web Application Security Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2019 Bruce Mayhew
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program; if
 * not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Getting Source ==============
 *
 * Source for this application is maintained at https://github.com/WebGoat/WebGoat, a repository for free software projects.
 */

package org.owasp.webgoat.lessons.sqlinjection.introduction;

import jakarta.annotation.PostConstruct;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(
    value = {
      "SqlStringInjectionHint5-1",
      "SqlStringInjectionHint5-2",
      "SqlStringInjectionHint5-3",
      "SqlStringInjectionHint5-4"
    })
public class SqlInjectionLesson5 extends AssignmentEndpoint {

  private final LessonDataSource dataSource;

  public SqlInjectionLesson5(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostConstruct
  public void createUser() {
    // HSQLDB does not support CREATE USER with IF NOT EXISTS so we need to do it in code (using
    // DROP first will throw error if user does not exists)
    try (Connection connection = dataSource.getConnection()) {
      try (var statement =
          connection.prepareStatement("CREATE USER unauthorized_user PASSWORD test")) {
        statement.execute();
      }
    } catch (Exception e) {
      // user already exists continue
    }
  }

  @PostMapping("/SqlInjection/attack5")
  @ResponseBody
  public AttackResult completed(String query) {
    createUser();
    return injectableQuery(query);
  }

  protected AttackResult injectableQuery(String query) {
    // Validate the query to prevent SQL injection attacks on the shared database
    if (!isValidLessonQuery(query)) {
      return failed(this)
          .output(
              "Invalid query. This lesson only accepts GRANT statements on the grant_rights table to"
                  + " unauthorized_user.<br> Your query was: "
                  + query)
          .build();
    }

    try (Connection connection = dataSource.getConnection()) {
      try (Statement statement =
          connection.createStatement(
              ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_UPDATABLE)) {
        statement.execute(query);
        if (checkSolution(connection)) {
          return success(this).build();
        }
        return failed(this).output("Your query was: " + query).build();
      }
    } catch (Exception e) {
      return failed(this)
          .output(
              this.getClass().getName() + " : " + e.getMessage() + "<br> Your query was: " + query)
          .build();
    }
  }

  /**
   * Validates that the query is a legitimate GRANT statement for the lesson and does not attempt to
   * access other schemas or execute malicious SQL. This prevents SQL injection attacks on the
   * shared database while maintaining the educational purpose of the lesson.
   *
   * @param query the SQL query to validate
   * @return true if the query is valid for this lesson, false otherwise
   */
  private boolean isValidLessonQuery(String query) {
    if (query == null || query.trim().isEmpty()) {
      return false;
    }

    String normalizedQuery = query.trim().toLowerCase();

    // Must be a GRANT statement
    if (!normalizedQuery.startsWith("grant")) {
      return false;
    }

    // Must reference grant_rights table (the lesson's target table)
    if (!normalizedQuery.contains("grant_rights")) {
      return false;
    }

    // Must grant to unauthorized_user (the lesson's target user)
    if (!normalizedQuery.contains("unauthorized_user")) {
      return false;
    }

    // Block attempts to access other schemas (CONTAINER, PUBLIC, or other user schemas)
    // Check for schema qualifiers with or without dots
    if (normalizedQuery.contains("container.") 
        || normalizedQuery.contains("container ") 
        || normalizedQuery.contains("public.")
        || normalizedQuery.contains("information_schema")) {
      return false;
    }

    // Block attempts to change schema context
    if (normalizedQuery.contains("set schema") 
        || normalizedQuery.contains("set current schema")
        || normalizedQuery.contains("set current_schema")) {
      return false;
    }

    // Block SQL injection attempts using semicolons to chain commands
    if (normalizedQuery.contains(";")) {
      return false;
    }

    // Block comment-based injection attempts
    if (normalizedQuery.contains("--") 
        || normalizedQuery.contains("/*") 
        || normalizedQuery.contains("*/")
        || normalizedQuery.contains("#")) {
      return false;
    }

    // Block subquery attempts
    if (normalizedQuery.contains("select") 
        || normalizedQuery.contains("union") 
        || normalizedQuery.contains("insert")
        || normalizedQuery.contains("update") 
        || normalizedQuery.contains("delete")
        || normalizedQuery.contains("drop")
        || normalizedQuery.contains("create")
        || normalizedQuery.contains("alter")
        || normalizedQuery.contains("truncate")
        || normalizedQuery.contains("exec")
        || normalizedQuery.contains("execute")) {
      return false;
    }

    // Block attempts to grant on multiple tables or to multiple users
    // by limiting to a single occurrence of key keywords
    int grantCount = countOccurrences(normalizedQuery, "grant");
    int toCount = countOccurrences(normalizedQuery, " to ");
    int onCount = countOccurrences(normalizedQuery, " on ");
    
    if (grantCount != 1 || toCount != 1 || onCount != 1) {
      return false;
    }

    return true;
  }

  /**
   * Counts the number of occurrences of a substring in a string.
   *
   * @param str the string to search in
   * @param substr the substring to search for
   * @return the number of occurrences
   */
  private int countOccurrences(String str, String substr) {
    int count = 0;
    int index = 0;
    while ((index = str.indexOf(substr, index)) != -1) {
      count++;
      index += substr.length();
    }
    return count;
  }

  private boolean checkSolution(Connection connection) {
    try {
      var stmt =
          connection.prepareStatement(
              "SELECT * FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES WHERE TABLE_NAME = ? AND GRANTEE ="
                  + " ?");
      stmt.setString(1, "GRANT_RIGHTS");
      stmt.setString(2, "UNAUTHORIZED_USER");
      var resultSet = stmt.executeQuery();
      return resultSet.next();
    } catch (SQLException throwables) {
      return false;
    }
  }
}
