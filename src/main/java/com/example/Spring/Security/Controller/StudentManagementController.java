package com.example.Spring.Security.Controller;

import com.example.Spring.Security.Model.Student;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {


    private final static List<Student> STUDENTS = Arrays.asList(
            new Student(1,"yousry"),
            new Student(2,"mohamed"),
            new Student(3,"mostafa")
    );
    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMINTRAINEE', 'ROLE_ADMIN')")
    public static List<Student> getStudents() {
        System.out.println("getStudents");
        return STUDENTS;
    }
    @PostMapping
    @PreAuthorize("hasAuthority('student:write')")
    public void registerNewStudent(@RequestBody Student student)
    {
        System.out.println("registerNewStudent");
        System.out.println(student);
    }
    @DeleteMapping(path = "{studentId}")
    @PreAuthorize("hasAuthority('student:write')")
    public void deleteStudent(@PathVariable("studentId") Integer studentId)
    {
        System.out.println("deleteStudent");
        System.out.println(studentId);
    }
    @PutMapping(path = "{studentId}")
    @PreAuthorize("hasAuthority('student:write')")
    public void updateStudent(@PathVariable("studentId") Integer studentId,
                              @RequestBody Student student)
    {
        System.out.println("updateStudent");
        System.out.println(String.format("%s %s", studentId, student));
    }
}