// Copyright 2016 Edward Curren
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
using System;

namespace OpenCKMS
{
    /// <summary>
    /// Struct ParentKey
    /// </summary>
    public class ParentKey
    {
        /// <summary>
        /// The identifier for the parent key.
        /// </summary>
        /// <see cref="KeyId"/>
        /// <value>The key identifier.</value>
        public Guid KeyId { get; set; }

        /// <summary>
        /// This element identifies how the parent key is related to the child key. 
        /// An example of the relationship is a mathematical function that was used 
        /// to create the child key using the parent key as one of the inputs. 
        /// The relationship might be indicated by the identification of the mathematical 
        /// function.
        /// </summary>
        /// <value>The nature of the relationship.</value>
        public string RelationshipNature { get; set; }
    }
}