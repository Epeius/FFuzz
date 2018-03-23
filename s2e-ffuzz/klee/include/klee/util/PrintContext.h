#ifndef PrintContext2_H_
#define PrintContext2_H_

#include <ostream>
#include <sstream>
#include <string>
#include <stack>
#include <iomanip>

/// PrintContext2 - Helper class for pretty printing.
/// It provides a basic wrapper around std::ostream that keeps track of
/// how many characters have been used on the current line.
///
/// It also provides an optional way keeping track of the various levels of indentation
/// by using a stack.
/// \sa breakLineI() , \sa pushIndent(), \sa popIndent()
class PrintContext2 {
private:
  std::ostream &os;
  std::stringstream ss;
  std::string newline;

  ///This is used to keep track of the stack of indentations used by
  /// \sa breakLineI()
  /// \sa pushIndent()
  /// \sa popIndent()
  std::stack<unsigned int> indentStack;

public:
  /// Number of characters on the current line.
  unsigned pos;

  PrintContext2(std::ostream &_os) : os(_os), newline("\n"), indentStack(), pos()
  {
	  indentStack.push(pos);
  }

  void setNewline(const std::string &_newline) {
    newline = _newline;
  }

  void breakLine(unsigned indent=0) {
    os << newline;
    if (indent)
      os << std::setw(indent) << ' ';
    pos = indent;
  }

  ///Break line using the indent on the top of the indent stack
  /// \return The PrintContext2 object so the method is chainable
  PrintContext2& breakLineI()
  {
	  breakLine(indentStack.top());
	  return *this;
  }

  ///Add the current position on the line to the top of the indent stack
  /// \return The PrintContext2 object so the method is chainable
  PrintContext2& pushIndent()
  {
	  indentStack.push(pos);
	  return *this;
  }

  ///Pop the top off the indent stack
  /// \return The PrintContext2 object so the method is chainable
  PrintContext2& popIndent()
  {
	  indentStack.pop();
	  return *this;
  }

  /// write - Output a string to the stream and update the
  /// position. The stream should not have any newlines.
  void write(const std::string &s) {
    os << s;
    pos += s.length();
  }

  template <typename T>
  PrintContext2 &operator<<(T elt) {
    ss.str("");
    ss << elt;
    write(ss.str());
    return *this;
  }

};


#endif /* PrintContext2_H_ */
