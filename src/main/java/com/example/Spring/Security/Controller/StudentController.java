package com.example.Spring.Security.Controller;

import com.example.Spring.Security.Model.Student;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/v1/students")
public class StudentController {

    private final static List<Student> STUDNETS= Arrays.asList(
            new Student(1,"yousry"),
            new Student(2,"mohamed"),
            new Student(3,"mostafa")
    );

    @GetMapping(path = "{studentId}")
    public Student getStudent(@PathVariable("studentId") Integer studentId)
    {
       return STUDNETS.stream()
                .filter(student -> studentId.equals(student.getId()))
                .findFirst()
                .orElseThrow(()-> new IllegalStateException("Student with id =" +studentId+" is not exists"));
    }
}
