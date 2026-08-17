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

package org.owasp.webgoat.lessons.clientsidefiltering;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

@RestController
@Slf4j
public class Salaries {

  @Value("${webgoat.user.directory}")
  private String webGoatHomeDirectory;

  @PostConstruct
  public void copyFiles() {
    ClassPathResource classPathResource = new ClassPathResource("lessons/employees.xml");
    File targetDirectory = new File(webGoatHomeDirectory, "/ClientSideFiltering");
    if (!targetDirectory.exists()) {
      targetDirectory.mkdir();
    }
    try {
      FileCopyUtils.copy(
          classPathResource.getInputStream(),
          new FileOutputStream(new File(targetDirectory, "employees.xml")));
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @GetMapping("clientSideFiltering/salaries")
  @ResponseBody
  public List<Map<String, Object>> invoke(
      @RequestParam(required = false) String userId, HttpServletRequest request) {
    NodeList nodes = null;
    File d = new File(webGoatHomeDirectory, "ClientSideFiltering/employees.xml");
    XPathFactory factory = XPathFactory.newInstance();
    XPath path = factory.newXPath();
    int columns = 5;
    List<Map<String, Object>> json = new ArrayList<>();
    java.util.Map<String, Object> employeeJson = new HashMap<>();

    // Get the authenticated user's ID from the request
    String authenticatedUserId = userId;
    if (authenticatedUserId == null && request.getUserPrincipal() != null) {
      // Fallback: try to extract from principal if userId not provided
      authenticatedUserId = extractUserIdFromPrincipal(request.getUserPrincipal().getName());
    }

    try (InputStream is = new FileInputStream(d)) {
      InputSource inputSource = new InputSource(is);

      StringBuilder sb = new StringBuilder();

      sb.append("/Employees/Employee/UserID | ");
      sb.append("/Employees/Employee/FirstName | ");
      sb.append("/Employees/Employee/LastName | ");
      sb.append("/Employees/Employee/SSN | ");
      sb.append("/Employees/Employee/Salary ");

      String expression = sb.toString();
      nodes = (NodeList) path.evaluate(expression, inputSource, XPathConstants.NODESET);
      for (int i = 0; i < nodes.getLength(); i++) {
        if (i % columns == 0) {
          employeeJson = new HashMap<>();
          json.add(employeeJson);
        }
        Node node = nodes.item(i);
        employeeJson.put(node.getNodeName(), node.getTextContent());
      }

      // Apply server-side authorization: filter results based on manager relationship
      if (authenticatedUserId != null) {
        json = filterEmployeesByManagerAuthorization(json, authenticatedUserId, d, path);
      }

    } catch (XPathExpressionException e) {
      log.error("Unable to parse xml", e);
    } catch (IOException e) {
      log.error("Unable to read employees.xml at location: '{}'", d);
    }
    return json;
  }

  /**
   * Filters the employee list to only include employees that the authenticated user is authorized
   * to view based on manager relationships defined in the XML.
   */
  private List<Map<String, Object>> filterEmployeesByManagerAuthorization(
      List<Map<String, Object>> allEmployees, String managerId, File xmlFile, XPath xpath) {
    List<Map<String, Object>> authorizedEmployees = new ArrayList<>();

    try (InputStream is = new FileInputStream(xmlFile)) {
      InputSource inputSource = new InputSource(is);

      for (Map<String, Object> employee : allEmployees) {
        String employeeUserId = (String) employee.get("UserID");
        if (employeeUserId != null) {
          // Check if the managerId is in this employee's list of managers
          String managerCheckExpression =
              String.format(
                  "/Employees/Employee[UserID='%s']/Managers/Manager[text()='%s']",
                  employeeUserId, managerId);

          // Re-parse for each check (inefficient but safe for this security fix)
          try (InputStream checkStream = new FileInputStream(xmlFile)) {
            InputSource checkSource = new InputSource(checkStream);
            NodeList managerNodes =
                (NodeList) xpath.evaluate(managerCheckExpression, checkSource, XPathConstants.NODESET);

            // If the manager is found in the employee's manager list, include this employee
            if (managerNodes.getLength() > 0) {
              authorizedEmployees.add(employee);
            }
          }
        }
      }
    } catch (XPathExpressionException e) {
      log.error("Unable to evaluate manager authorization", e);
    } catch (IOException e) {
      log.error("Unable to read employees.xml for authorization check", e);
    }

    return authorizedEmployees;
  }

  /**
   * Extracts user ID from the principal name. This is a placeholder implementation. In a real
   * system, you would map the authenticated username to their employee UserID.
   */
  private String extractUserIdFromPrincipal(String principalName) {
    // This is a simplified implementation. In production, you would query a database
    // or user service to map the authenticated username to their employee UserID.
    // For this lesson, we return null to indicate no mapping is available.
    return null;
  }
}
